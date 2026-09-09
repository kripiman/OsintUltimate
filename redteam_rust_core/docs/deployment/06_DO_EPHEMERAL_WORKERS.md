# 06 — DigitalOcean Ephemeral Workers

**Role**: Data plane. Short-lived droplets (TTL 6h) execute active scans against authorized targets. Spawn from **Box2**, self-destroy on completion. Workers receive interactsh OOB config from `secrets.env` to generate callback payloads pointing at Box4.

**Prerequisites**: `03_BOX2_COORDINATOR.md`, `05_BOX4_INTERACTSH.md`, `05_TAILSCALE_MESH.md`, `08_SECRETS_MANAGEMENT.md`. Worker auth-key and interactsh token in secrets bundle.

> [!IMPORTANT]
> **Implementation status (verified against `src/` 2026-06-05).** V15.6 UPDATE: Core gaps closed. The worker binary runs **on** the DO droplet so `nmap -sS`, UDP, OS-detection and exploitation plugins execute from DO's IP (they need raw sockets and cannot traverse a SOCKS5 egress proxy).
>
> | Component | Status |
> |---|---|
> | Worker binary `--worker` consuming `scan_queue` | **Implemented** (`src/boot/worker.rs`) |
> | `--enqueue-only` (queue targets from Oracle without scanning) | **Implemented** (`src/boot/runtime.rs`) |
> | Oracle ban-prevention gate (`is_oracle_cloud()` → blocks Scanning+) | **Implemented** (`src/boot/runtime.rs`) |
> | DO droplet auto-provisioning as **proxy** | **Implemented** — `create_droplet` installs SOCKS5/Shadowsocks/Hysteria |
> | DO droplet auto-provisioning as **worker** | **Implemented** — `create_worker_droplet()` renders inline cloud-init with systemd + nmap + masscan + binary download. No Tailscale auto-join yet. |
> | Oracle coordinator auto-spawns DO workers on pending jobs | **Implemented** — `runtime.rs` spawns a polling task that checks `scan_queue` and calls `create_worker_droplet()` when `pending > 0 && active_workers == 0`. |
> | `DO_DROPLET_SIZE` env var | **Implemented** — read by `create_droplet`. Defaults to `s-1vcpu-1gb` for workers, `s-1vcpu-512mb` for proxies. |
> | NATS as worker task transport | **PLANNED** — NATS is still **output sink only**. |
>
> **Required env vars for worker spawn:**
> - `DIGITALOCEAN_TOKEN` — DO API token
> - `DATABASE_URL` — PostgreSQL URL for workers to connect
> - `DO_WORKER_BINARY_URL` — HTTPS URL to pre-built x86_64 musl binary
> - `DO_DROPLET_SIZE` — e.g. `s-1vcpu-1gb` (optional)
> - `SCOPE_ID`, `INTERACTSH_URL`, `INTERACTSH_TOKEN` — injected into worker env
>
> **To deploy today:**
> 1. **Manual (C):** bake snapshot (§1), spawn droplet, run `--worker`.
> 2. **Auto (A):** run coordinator on Oracle with `--max-layer passive` + `DIGITALOCEAN_TOKEN` + `DATABASE_URL`. Use `--enqueue-only` to queue targets. Coordinator auto-spawns DO workers when queue is non-empty.

---

## 1. Pre-baked snapshot — preferred bootstrap

Building from scratch every spawn costs 5+ minutes. Build a snapshot once, reuse for 90 days.

### 1.1 Provision template droplet

```bash
doctl compute droplet create mimikri-worker-template \
  --image ubuntu-22-04-x64 \
  --size s-1vcpu-1gb \
  --region nyc3 \
  --ssh-keys "$DO_SSH_FINGERPRINT" \
  --enable-private-networking \
  --enable-monitoring \
  --tag-names purpose:redteam-template \
  --wait
```

### 1.2 Provision tools

```bash
ssh root@<template-ip>

# Update + minimal install
apt update && apt full-upgrade -y
apt install -y \
  nmap masscan dnsutils whois \
  curl ca-certificates gnupg jq \
  ufw fail2ban auditd apparmor-utils \
  python3 python3-pip
apt autoremove --purge -y

# Tailscale
curl -fsSL https://tailscale.com/install.sh | sh

# Apply base hardening (subset of 01_BASE_HARDENING.md — sysctl, SSH, UFW skeleton, auditd)
# See §1.3 below for the exact subset
```

### 1.3 Worker-specific hardening

Workers have different constraints than Box1/2/3:
- No persistent operator access (no opsec user; SSH disabled after Tailscale up)
- All inbound from internet blocked
- Outbound to anywhere allowed (it's the scanner)
- TTL-bound — destruction guaranteed by cloud-init at 6h

`/etc/ufw/before.rules.d/mimikri.conf`:
```
# Inbound: only Tailscale
-A ufw-before-input -i tailscale0 -j ACCEPT
-A ufw-before-input -i lo -j ACCEPT
-A ufw-before-input -j DROP

# Outbound: allow all (this is the scanner)
-A ufw-before-output -j ACCEPT
```

```bash
# Same sysctl set as 01_BASE_HARDENING.md §6
# Same SSH config as 01 §4, but with PermitRootLogin no AND no operator user
# Disable password login entirely

# auditd — minimal set
cat > /etc/audit/rules.d/99-worker.rules <<'EOF'
-D
-b 4096
-f 1
-a always,exit -F arch=b64 -F euid=0 -S execve -k root_exec
-w /usr/local/bin/redteam_rust_core -p x -k worker_exec
-e 2
EOF
augenrules --load
```

### 1.4 Install worker binary

```bash
# Transfer pre-built x86_64 musl binary from Box1 Object Storage
# NOTE: DO standard droplets are x86_64 (ubuntu-22-04-x64 in §1.1), NOT ARM.
# Build target: x86_64-unknown-linux-musl. The Oracle boxes are ARM64; the DO worker is a separate x86_64 artifact.
curl -fsSL -o /usr/local/bin/redteam_rust_core \
  "https://objectstorage.<region>.oraclecloud.com/p/<signed-url>/redteam_rust_core-v0.1.0"
chmod 755 /usr/local/bin/redteam_rust_core

# Verify signature
curl -fsSL -o /tmp/redteam.asc \
  "https://objectstorage.<region>.oraclecloud.com/p/<signed-url>/redteam_rust_core-v0.1.0.asc"
gpg --import /etc/mimikri/operator.pubkey
gpg --verify /tmp/redteam.asc /usr/local/bin/redteam_rust_core
```

### 1.5 Worker AppArmor profile

`/etc/apparmor.d/usr.local.bin.redteam_rust_core`:
```apparmor
#include <tunables/global>
/usr/local/bin/redteam_rust_core {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  #include <abstractions/openssl>

  capability net_raw,             # nmap SYN scan
  capability net_admin,           # raw sockets
  capability net_bind_service,
  network inet stream,
  network inet6 stream,
  network inet dgram,
  network inet raw,               # nmap raw probes
  network netlink raw,

  /etc/ssl/certs/** r,
  /etc/resolv.conf r,
  /usr/bin/nmap mrix,
  /usr/bin/masscan mrix,

  /var/lib/mimikri/** rwk,
  /tmp/** rwk,

  deny /home/** rwklx,
  deny /root/** rwklx,
  deny /etc/shadow r,
  deny capability sys_module,
  deny capability sys_admin,
}
```

```bash
apparmor_parser -r /etc/apparmor.d/usr.local.bin.redteam_rust_core
aa-enforce /etc/apparmor.d/usr.local.bin.redteam_rust_core
```

### 1.6 Snapshot

```bash
# On operator workstation
doctl compute droplet-action snapshot <template-droplet-id> \
  --snapshot-name "mimikri-worker-v0.1.0-$(date +%F)" \
  --wait

# Get snapshot ID
SNAPSHOT_ID=$(doctl compute snapshot list --resource droplet \
  --format ID,Name | grep mimikri-worker-v0.1.0 | head -1 | awk '{print $1}')
echo "SNAPSHOT_ID=$SNAPSHOT_ID" >> /opt/mimikri/etc/runtime.env

# Destroy template (no longer needed)
doctl compute droplet delete <template-droplet-id> --force
```

> [!IMPORTANT]
> Re-bake snapshot monthly: pull latest Tailscale, latest nmap, latest worker binary. Old snapshots accumulate vulnerabilities.

---

## 2. Cloud-init user-data (per spawn)

> [!NOTE]
> **IMPLEMENTED (V15.6).** `digital_ocean.rs::generate_user_data(ProxyMode::Worker)` now renders an inline worker cloud-config directly. No separate `infrastructure/cloud-init-worker.yaml` file is required. The systemd unit below is the **reference template** that the code renders automatically. Use it for hand-tweaked deployments or snapshot baking.

```yaml
#cloud-config

# Time
timezone: UTC
ntp:
  enabled: true
  servers:
    - 0.pool.ntp.org
    - 1.pool.ntp.org

# SSH disabled — no operator access
ssh_pwauth: false
disable_root: true
ssh:
  emit_keys_to_console: false

# Hostname (DROPLET_ID injected by spawn code)
hostname: mimikri-worker-${DROPLET_ID}
fqdn: mimikri-worker-${DROPLET_ID}.local

# Disable swap
runcmd:
  - swapoff -a
  - sed -i '/swap/s/^/#/' /etc/fstab

  # Tailscale join
  - curl -fsSL https://tailscale.com/install.sh | sh
  - tailscale up
      --auth-key=${TAILSCALE_AUTH_KEY}
      --advertise-tags=tag:redteam-worker
      --hostname=mimikri-worker-${DROPLET_ID}
      --ephemeral
      --accept-routes=false
      --accept-dns=false
      --ssh=false
      --reset

  # Wait for tailnet
  - bash -c 'for i in {1..30}; do tailscale ip -4 && break || sleep 2; done'

  # Verify connectivity to Box1 Postgres
  - bash -c 'until nc -zv mimikri-box1.tail-XXXX.ts.net 5432; do sleep 2; done'

  # Drop SSH after tailnet is up
  - systemctl stop ssh
  - systemctl disable ssh
  - ufw delete allow 22/tcp 2>/dev/null || true

  # Run worker
  - |
    cat > /etc/systemd/system/redteam-worker.service <<EOF
    [Unit]
    Description=Mimikri Worker
    After=network-online.target tailscaled.service
    Wants=network-online.target

    [Service]
    Type=simple
    User=root
    Environment="DATABASE_URL=${DATABASE_URL}"
    Environment="NATS_URL=${NATS_URL}"
    Environment="RUST_LOG=info"
    Environment="OTEL_ENDPOINT=${OTEL_ENDPOINT}"
    Environment="SCOPE_ID=${SCOPE_ID}"
    Environment="REDTEAM_AUTHORIZED_SCOPE=${SCOPE_ID}"
    Environment="INTERACTSH_URL=${INTERACTSH_URL}"
    Environment="INTERACTSH_TOKEN=${INTERACTSH_TOKEN}"
    Environment="SHUFFLEDNS_PATH=/usr/bin/shuffledns"
    Environment="MASSDNS_PATH=/usr/bin/massdns"
    Environment="SHUFFLEDNS_RESOLVERS=/opt/mimikri-ai/etc/resolvers.txt"
    Environment="SHUFFLEDNS_WORDLIST=/opt/mimikri-ai/etc/subdomains.txt"
    Environment="S3SCANNER_PATH=/usr/local/bin/s3scanner"
    Environment="S3SCANNER_WORDLIST=/opt/mimikri-ai/etc/buckets.txt"
    Environment="KXSS_PATH=/usr/bin/kxss"
    Environment="GHAURI_PATH=/usr/local/bin/ghauri"
    Environment="SSRFMAP_PATH=/opt/mimikri-ai/bin/ssrfmap/ssrfmap.py"
    Environment="NOSQLMAP_PATH=/opt/mimikri-ai/bin/nosqlmap/nosqlmap.py"
    Environment="GOPHERUS_PATH=/opt/mimikri-ai/bin/gopherus/gopherus.py"
    Environment="CLAIRVOYANCE_WORDLIST=/opt/mimikri-ai/etc/graphql.txt"
    ExecStart=/usr/local/bin/redteam_rust_core \
      --worker \
      --postgres-url \${DATABASE_URL} \
      --node-id do-${DROPLET_ID} \
      --concurrency 4 \
      --soft-mem-limit-mb 600
    ExecStopPost=/usr/local/sbin/self-destruct.sh
    Restart=no
    TimeoutStopSec=60s
    RuntimeMaxSec=21600

    NoNewPrivileges=yes
    ProtectSystem=strict
    ProtectHome=yes
    PrivateTmp=yes
    ProtectKernelTunables=yes
    ProtectKernelModules=yes
    ProtectKernelLogs=yes
    ProtectControlGroups=yes
    LockPersonality=yes
    RestrictRealtime=yes
    ReadWritePaths=/var/lib/mimikri /tmp
    SystemCallArchitectures=native
    SystemCallFilter=@system-service
    SystemCallFilter=~@mount @debug @cpu-emulation @keyring @obsolete @raw-io @reboot @swap @privileged
    AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN CAP_NET_BIND_SERVICE
    CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN CAP_NET_BIND_SERVICE
    MemoryMax=900M
    LimitNOFILE=8192

    [Install]
    WantedBy=multi-user.target
    EOF
    systemctl daemon-reload
    systemctl enable --now redteam-worker

# Self-destruct script: DELETE droplet via DO API on exit
write_files:
  - path: /usr/local/sbin/self-destruct.sh
    permissions: '0700'
    owner: root:root
    content: |
      #!/bin/sh
      DROPLET_ID=$(curl -fsSL http://169.254.169.254/metadata/v1/id)
      curl -fsSL -X DELETE \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${DO_TOKEN}" \
        "https://api.digitalocean.com/v2/droplets/$DROPLET_ID" || true
      sleep 5
      poweroff -f
```

> [!NOTE]
> **IMPLEMENTED (V15.6).** `generate_user_data(ProxyMode::Worker)` renders the inline worker cloud-config directly. Values (`TAILSCALE_AUTH_KEY`, `DATABASE_URL`, `SCOPE_ID`, `INTERACTSH_URL`, `INTERACTSH_TOKEN`, `DO_TOKEN`) are sourced from environment variables on **Box2** at spawn time. The `self-destruct.sh` script (injected via `write_files`) uses the DO metadata service (`169.254.169.254/metadata/v1/id`) and the injected `DO_TOKEN` to DELETE the droplet upon worker exit.

---

### Spawn flow (**Box2** → DO)

> [!NOTE]
> **IMPLEMENTED (V15.6).** `digital_ocean.rs::create_worker_droplet(name, region)` renders worker cloud-init, reads `DO_DROPLET_SIZE` from env (default `s-1vcpu-1gb`), tags `["osint-ultimate","ephemeral"]`, and auto-installs nmap/masscan/Tailscale. The kill-switch and reaper enumerate droplets via `GET /v2/droplets?tag_name=osint-ultimate`.

The intended worker spawn performs:

1. Pull `DO_TOKEN` from Vault
2. Pull `TAILSCALE_AUTH_KEY` (worker ephemeral) from Vault
3. Render cloud-init template with scope-specific values
4. `POST https://api.digitalocean.com/v2/droplets`:
   ```json
   {
     "name": "mimikri-worker-${UUID}",
     "region": "${REGION}",
     "size": "s-1vcpu-1gb",
     "image": "${SNAPSHOT_ID}",
     "ssh_keys": [],
     "backups": false,
     "ipv6": false,
     "monitoring": false,
     "tags": ["osint-ultimate", "ephemeral", "campaign:${SCOPE_ID}"],
     "user_data": "${BASE64_CLOUD_INIT}",
     "vpc_uuid": null
   }
   ```
5. Record droplet_id in Postgres `workers` table
6. Wait for tailnet appearance (poll `tailscale status` for `mimikri-worker-${id}`)
7. Worker begins polling `scan_queue`

> Tag note: the code's destroy/kill-switch path keys off the **`osint-ultimate`** tag, so any worker spawn must include it (not the legacy `purpose:redteam-ephemeral` shown in older drafts) or the janitor will not find the droplet.

---

## 4. Destroy flow

### 4.1 Normal — worker exits cleanly

1. Worker drains `scan_queue` jobs for its `claimed_by` filter
2. `redteam_rust_core --worker` exits with status 0
3. `self-destruct.sh` runs (ExecStopPost):
   - Reads droplet ID from `169.254.169.254/metadata/v1/id`
   - Calls `DELETE /v2/droplets/${id}` via DO API
   - Falls back to `poweroff -f` if API call fails
4. Droplet destroyed (billing stops immediately)
5. If self-destruct fails → reaper task on coordinator detects `off` droplet and destroys it within 5 min
6. Tailnet device entry auto-expires (ephemeral key)

### 4.2 TTL-forced — 6h systemd hard limit

1. `RuntimeMaxSec=21600` in systemd service → SIGTERM at 6h regardless of scan state
2. `ExecStopPost=self-destruct.sh` fires → DELETE droplet via DO API
3. Belt-and-suspenders: coordinator reaper task also scans for stale/off droplets every 5 min

### 4.3 Kill-switch — operator interrupt

1. Operator sends SIGINT (Ctrl+C) to `redteam-coordinator` on Box1
2. `KillSignal=SIGINT` in systemd → `tokio::signal::ctrl_c()` handler
3. Coordinator calls `destroy_all_ephemeral_droplets()`:
   - `GET /v2/droplets?tag_name=osint-ultimate`
   - For each: `DELETE /v2/droplets/${id}`
4. Verify in DO console no droplets remain with the `osint-ultimate` tag

> [!IMPORTANT]
> Drill the kill-switch quarterly. Confirmed working = all droplets gone within 30s of Ctrl+C, no orphan billing the next day.

---

## 5. Cost ceiling enforcement

**Cost ceiling tracking** uses **Box2** env vars. Hard ceiling:

`/opt/mimikri/etc/runtime.env`:
```env
MAX_CONCURRENT_DROPLETS=8
MAX_CAMPAIGN_BUDGET_USD=5         # per campaign
MAX_MONTHLY_BUDGET_USD=15         # absolute cap
```

`redteam_rust_core` checks budget before spawning. If exceeded → refuse spawn + alert via Loki.

For belt-and-suspenders, set hard cap in DO console:
- **Settings → Billing → Spending Alerts → $20/month threshold**
- If exceeded, DO sends email; manual intervention to suspend account

---

## 6. Network isolation between droplets

DO does not place droplets in a private VPC unless requested. Default: all DO IPs reachable from internet. Mitigation:
- Each droplet's UFW blocks inbound from internet (`§1.3`)
- Workers only listen on `tailscale0`
- Inter-worker comms forbidden by Tailscale ACL (`05_TAILSCALE_MESH.md §3`)

To strengthen further: create a DO VPC, place workers inside:

```bash
doctl vpcs create --name mimikri-workers --region nyc3 --ip-range 10.20.0.0/16
# Update spawn payload: "vpc_uuid": "<vpc-id>"
```

But VPC adds complexity and is not free in all regions. Tailscale + UFW already provides equivalent isolation.

---

## 7. Verification

```bash
# Snapshot present
doctl compute snapshot list --resource droplet | grep mimikri-worker

# Test spawn (Box2)
ssh opsec@mimikri-box2
sudo -u mimikri /usr/local/bin/redteam_rust_core \
  --spawn-test-droplet \
  --scope-id test-001 \
  --postgres-url "$DATABASE_URL"
# Expected: droplet appears in DO console + tailnet within 90s

# Worker polls queue
psql -h mimikri-box2 -U mimikri redteam -c \
  "SELECT id, status, claimed_by FROM scan_queue ORDER BY id DESC LIMIT 5;"

# Worker self-destructs
# Force exit:
sudo -u mimikri /usr/local/bin/redteam_rust_core --kill-switch --scope-id test-001
# 30s later:
doctl compute droplet list --tag-name campaign:test-001
# Expected: empty
```

---

## 8. Pitfalls

| Pitfall | Symptom | Fix |
|---|---|---|
| Snapshot stale (3 months old) | Worker binary outdated | Rebake monthly cron |
| Tailscale ephemeral key expired | Workers fail to join tailnet | Rotate per `08 §4` (90d) |
| Snapshot ID changes after rebake | Code references old ID | Read from `/opt/mimikri/etc/runtime.env` at spawn time |
| Cloud-init script size > 64KB | DO rejects | Move to base64 + compress; or fetch from Object Storage in `runcmd` |
| Worker dies before tailnet up | Becomes orphan | `at +6h shutdown` still fires; janitor cleans up |
| DO spending alert ignored | Surprise bill | Audit weekly via `doctl compute droplet list --format Name,Created,Memory,VCPUs` |
| Region selected outside scope geo | Latency / target geo policies | Spawn in region near target |
| `osint-ultimate` tag forgotten | Janitor/kill-switch cannot find droplet (queries `tag_name=osint-ultimate`) | Validate in spawn code: `assert!(tags.contains("osint-ultimate"))` |
| Worker exposes SSH momentarily before disable | Brief attack window | UFW default-deny inbound before SSH service starts |
| interactsh token not injected in cloud-init | Workers generate payloads but Box4 rejects them | Verify `INTERACTSH_TOKEN` in `secrets.env` and cloud-init env block |
| interactsh server down (Box4) | OOB callbacks missed; scans continue but blind findings unconfirmed | Restart interactsh on Box4; restart scan session to re-inject fresh payloads |

Proceed to `07_DASHBOARD_PUBLIC_ACCESS.md`.
