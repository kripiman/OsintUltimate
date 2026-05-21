# 06 — DigitalOcean Ephemeral Workers

**Role**: Data plane. Short-lived droplets (TTL 6h) execute active scans against authorized targets. Spawn from Box1, self-destroy on completion.

**Prerequisites**: `02_BOX1_COORDINATOR.md`, `05_TAILSCALE_MESH.md`, `08_SECRETS_MANAGEMENT.md`. Worker auth-key in Vault.

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
# Transfer pre-built ARM64 musl binary from Box1 Object Storage
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

`infrastructure/digital_ocean.rs` injects a cloud-init script when calling `POST /v2/droplets`. Template stored in `redteam_rust_core/infrastructure/cloud-init-worker.yaml`:

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

  # Self-destruct timer — UNCONDITIONAL
  # Even if scan hangs, droplet dies at 6h
  - at -M now + 6 hours <<< 'poweroff -f'

  # Tailscale join
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
    ExecStart=/usr/local/bin/redteam_rust_core \
      --worker \
      --postgres-url \${DATABASE_URL} \
      --node-id do-${DROPLET_ID} \
      --concurrency 4 \
      --soft-mem-limit-mb 600
    ExecStopPost=/usr/local/sbin/worker-finalize.sh
    Restart=no
    TimeoutStopSec=60s

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

# Finalize script: when worker exits, shut down
write_files:
  - path: /usr/local/sbin/worker-finalize.sh
    permissions: '0700'
    owner: root:root
    content: |
      #!/usr/bin/env bash
      # Worker exited (queue drained or fatal). Drain pending NATS,
      # then power off so Box1 can clean up the droplet record.
      sleep 30
      tailscale logout || true
      poweroff -f

# Final lockdown
power_state:
  delay: 'now'
  mode: poweroff
  message: 'Worker shutdown via finalize'
  condition: 'test ! -f /etc/redteam-active'
```

> [!NOTE]
> The cloud-init template is rendered by `infrastructure/digital_ocean.rs` with the campaign-specific values (`DROPLET_ID`, `TAILSCALE_AUTH_KEY`, `DATABASE_URL`, `SCOPE_ID`). These values come from `/run/mimikri/secrets.env` (tmpfs, populated by the operator-side `unlock-remote.sh` flow in `08_SECRETS_MANAGEMENT.md`). They are never embedded in the snapshot and never written to Box1 disk.

---

## 3. Spawn flow (Box1 → DO)

`infrastructure/digital_ocean.rs::spawn()` performs:

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
     "tags": ["purpose:redteam-ephemeral", "campaign:${SCOPE_ID}", "spawned-by:box1"],
     "user_data": "${BASE64_CLOUD_INIT}",
     "vpc_uuid": null
   }
   ```
5. Record droplet_id in Postgres `workers` table
6. Wait for tailnet appearance (poll `tailscale status` for `mimikri-worker-${id}`)
7. Worker begins polling `scan_queue`

---

## 4. Destroy flow

### 4.1 Normal — worker exits cleanly

1. Worker drains `scan_queue` jobs for its `claimed_by` filter
2. `redteam_rust_core --worker` exits with status 0
3. `worker-finalize.sh` runs (ExecStopPost), `poweroff -f`
4. Droplet enters `off` state
5. Box1 polling loop detects `off` → calls DELETE on droplet
6. Tailnet device entry auto-expires (ephemeral key)

### 4.2 TTL-forced — 6h cloud-init `at` timer

1. `at +6h shutdown -h now` fires regardless of scan state
2. Droplet powers off
3. Box1 or Box3 janitor (`04_BOX3 §5`) issues DELETE

### 4.3 Kill-switch — operator interrupt

1. Operator sends SIGINT (Ctrl+C) to `redteam-coordinator` on Box1
2. `KillSignal=SIGINT` in systemd → `tokio::signal::ctrl_c()` handler
3. Coordinator calls `destroy_all_ephemeral_droplets()`:
   - `GET /v2/droplets?tag_name=campaign:${SCOPE_ID}`
   - For each: `DELETE /v2/droplets/${id}`
4. Verify in DO console no droplets remain with the campaign tag

> [!IMPORTANT]
> Drill the kill-switch quarterly. Confirmed working = all droplets gone within 30s of Ctrl+C, no orphan billing the next day.

---

## 5. Cost ceiling enforcement

Box1 tracks DO spend via tag-based monitoring. Hard ceiling:

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

# Test spawn (Box1)
ssh opsec@mimikri-box1
sudo -u mimikri /usr/local/bin/redteam_rust_core \
  --spawn-test-droplet \
  --scope-id test-001 \
  --postgres-url "$DATABASE_URL"
# Expected: droplet appears in DO console + tailnet within 90s

# Worker polls queue
psql -h mimikri-box1 -U mimikri redteam -c \
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
| `purpose:redteam-ephemeral` tag forgotten | Janitor cannot find droplet | Validate in spawn() code: `assert!(tags.contains("purpose:redteam-ephemeral"))` |
| Worker exposes SSH momentarily before disable | Brief attack window | UFW default-deny inbound before SSH service starts |

Proceed to `07_DASHBOARD_PUBLIC_ACCESS.md`.
