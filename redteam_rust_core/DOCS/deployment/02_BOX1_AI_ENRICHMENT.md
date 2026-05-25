# 02 — Box1: AI Enrichment (Ollama Client + Router + BloodHound) + OCI Paid Services ⚠️ Sacrificable

**Role**: AI/LLM inference, findings classification, compression, BloodHound post-processing, bug bounty auto-submit. Also hosts OCI paid services (Object Storage, Block Volume Backup of Box2, VSS, Logging Analytics) funded by the student credit.

> [!WARNING]
> Box1 uses a student Oracle account linked to a university email. The university may revoke this email after graduation, causing Oracle to suspend the tenancy. Box1 is **intentionally sacrificable**: losing it stops AI enrichment but does **not** stop Bug Bounty scanning operations, which are coordinated by Box2.

**Prerequisites**: `01_BASE_HARDENING.md`, `05_TAILSCALE_MESH.md`, `08_SECRETS_MANAGEMENT.md`, **Box2 reachable on tailnet** (Box2 holds the Postgres primary that Box1 reads from).

**Specs**: 4 OCPU ARM / 24GB RAM, 200GB block storage, Oracle student tenancy ($300 credit for paid services).

---

## 1. Service user + directory layout

```bash
sudo groupadd -r mimikri
sudo useradd -r -g mimikri -d /opt/mimikri -s /sbin/nologin -c "Mimikri RedTeam Coordinator" mimikri

sudo install -d -o root -g mimikri -m 0750 /opt/mimikri
sudo install -d -o mimikri -g mimikri -m 0750 /opt/mimikri/bin
sudo install -d -o mimikri -g mimikri -m 0750 /opt/mimikri/etc
sudo install -d -o mimikri -g mimikri -m 0750 /opt/mimikri/workspace
sudo install -d -o mimikri -g mimikri -m 0750 /opt/mimikri/workspace/logs
sudo install -d -o mimikri -g mimikri -m 0700 /opt/mimikri/workspace/secrets   # ephemeral runtime only
sudo install -d -o mimikri -g mimikri -m 0755 /var/log/mimikri
```

`/opt/mimikri/bin` is read-only for mimikri (root-managed binaries).
`/opt/mimikri/workspace` is the only writable path (sandboxed via systemd `ReadWritePaths`).

---

## 2. PostgreSQL (read-only replica — optional)

> [!IMPORTANT]
> The **Postgres primary** lives on Box2 (permanent coordinator).
> See `03_BOX2_COORDINATOR.md` §2 for the primary installation.
>
> Box1 previously hosted a primary (legacy docs). That architecture was moved
> to Box2 per `HYBRID_DEPLOYMENT_TOPOLOGY.md` §11. Do NOT run a primary here.
>
> If you need a local read-only replica for latency reduction, follow the
> standard Postgres streaming replication docs pointing upstream to Box2.

### 2.1 LUKS encryption (applies to any Postgres data volume)

Oracle block volumes are encrypted at rest by default (AES-256, OCI managed). Confirm:
```bash
sudo blkid | grep -i crypt   # optional LUKS layer
oci bv volume get --volume-id <ocid> --query 'data."is-hydrated"'
```

If you want application-layer LUKS in addition:
```bash
# (Only on dedicated /var/lib/postgresql volume)
sudo cryptsetup luksFormat /dev/oracleoci/oraclevdb
sudo cryptsetup open /dev/oracleoci/oraclevdb postgres_crypt
sudo mkfs.ext4 /dev/mapper/postgres_crypt
echo 'postgres_crypt UUID=<luks-uuid> none luks,discard' | sudo tee -a /etc/crypttab
echo '/dev/mapper/postgres_crypt /var/lib/postgresql ext4 defaults,nodev,nosuid 0 2' | sudo tee -a /etc/fstab
```

> [!NOTE]
> LUKS unlock at boot requires a keyfile. Either ship it via the same `age` + YubiKey + SSH flow used for `secrets.env` (operator unlocks LUKS during the same post-reboot session), or skip LUKS entirely and rely on Oracle's native block-volume encryption-at-rest (AES-256). Skipping LUKS is acceptable per `00_OVERVIEW.md` §2.3 because physical datacenter compromise is out of threat-model scope.

---

## 3. NATS client configuration

> [!IMPORTANT]
> The **NATS mesh hub** lives on Box2 (permanent coordinator).
> See `03_BOX2_COORDINATOR.md` §3 for the hub installation.
>
> Box1 is a NATS client only. It connects to `nats://mimikri-box2:4222`.
> Box1 previously hosted the hub (legacy docs) — moved to Box2.

Box1 needs NATS credentials (`ACC_REDTEAM` JWT) to publish enrichment results
and subscribe to swarm coordination topics. Credentials are delivered via
`secrets.env.age` unlock (see `08_SECRETS_MANAGEMENT.md`).

---

## 4. `redteam_rust_core` binary deployment

### 4.1 Build (operator workstation, reproducible)

```bash
cd /path/to/OsintUltimate
RUSTFLAGS='-C target-feature=+crt-static' cargo build --release \
  --package redteam_rust_core \
  --target aarch64-unknown-linux-musl \
  --features "bug-bounty"     # do NOT include sovereign for open-source / bug bounty deploy

# Sign artifact (operator gpg key)
gpg --detach-sign --armor target/aarch64-unknown-linux-musl/release/redteam_rust_core
sha256sum target/aarch64-unknown-linux-musl/release/redteam_rust_core > redteam.sha256
gpg --clearsign --output redteam.sha256.asc redteam.sha256
```

### 4.2 Upload + install on Box1

```bash
# Transfer via Tailscale
scp -i ~/.ssh/mimikri_box1 \
    target/aarch64-unknown-linux-musl/release/redteam_rust_core \
    redteam_rust_core.asc \
    redteam.sha256.asc \
    opsec@mimikri-box1:/tmp/

ssh opsec@mimikri-box1
cd /tmp

# Verify signature
gpg --verify redteam_rust_core.asc redteam_rust_core
gpg --verify redteam.sha256.asc
sha256sum -c redteam.sha256

# Install
sudo install -o root -g mimikri -m 0750 redteam_rust_core /usr/local/bin/

# AppArmor profile
sudo tee /etc/apparmor.d/usr.local.bin.redteam_rust_core > /dev/null <<'EOF'
#include <tunables/global>
/usr/local/bin/redteam_rust_core {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  #include <abstractions/openssl>

  capability net_bind_service,
  network inet stream,
  network inet6 stream,
  network inet dgram,
  network netlink raw,

  /etc/ssl/certs/** r,
  /etc/resolv.conf r,
  /proc/sys/net/core/somaxconn r,

  /opt/mimikri/** rwk,
  /var/log/mimikri/** rwk,

  # Postgres client
  /var/run/postgresql/.s.PGSQL.5432 rw,

  # Deny dangerous
  deny /etc/shadow r,
  deny /root/** rwklx,
  deny /home/** rwklx,
  deny capability sys_admin,
  deny capability sys_module,
  deny capability sys_ptrace,
}
EOF
sudo apparmor_parser -r /etc/apparmor.d/usr.local.bin.redteam_rust_core
sudo aa-enforce /etc/apparmor.d/usr.local.bin.redteam_rust_core
```

---

## 5. Coordinator configuration

`/opt/mimikri/etc/runtime.env` (non-secret, see `08_SECRETS_MANAGEMENT.md` §3.4):

```env
SCOPE_ID=acme-2026-q2
RUST_LOG=info,sqlx=warn,h2=warn
OTEL_ENDPOINT=http://mimikri-box3:4317
NATS_URL=nats://mimikri-box2:4222
OLLAMA_URL=http://mimikri-box2:11434
CERTSTREAM_KEYWORDS=acme,evilcorp
REDTEAM_AUTHORIZED_SCOPE=acme-2026-q2
APPROVAL_TIMEOUT_SECS=300

# NOT destructive by default - operator opts in per campaign
# REDTEAM_DESTRUCTIVE=1

# Concurrency tuning for 4c/24GB ARM
COORDINATOR_CONCURRENCY=8
COORDINATOR_SOFT_MEM_LIMIT_MB=8000

# Bug bounty
H1_HANDLE=your_h1_handle
SCOPE_SYNC=true
```

`/opt/mimikri/etc/policy.json` (your scope policy — see `redteam_rust_core/policy.json.example`):
```jsonc
{
  "programs": {
    "acme-2026-q2": {
      "in_scope":     ["*.acme.com", "api.acme.io"],
      "out_of_scope": ["admin.acme.com", "internal.acme.com"]
    }
  }
}
```

### 5.1 Launcher (reads secrets from tmpfs unlocked via `08_SECRETS_MANAGEMENT.md`)

`/opt/mimikri/bin/run-coordinator.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

# Non-secret config
set -a
. /opt/mimikri/etc/runtime.env
set +a

# Secrets already in /run/mimikri/secrets.env (tmpfs, populated by operator via age-YubiKey unlock).
# systemd unit's EnvironmentFile=/run/mimikri/secrets.env already exposed them as env vars; this
# launcher just sanity-checks and execs.

[[ -z "${DATABASE_URL:-}" ]] && {
  echo "FATAL: DATABASE_URL not present — operator must run unlock-remote.sh from workstation" >&2
  exit 1
}

exec /usr/local/bin/redteam_rust_core \
  --target-policy /opt/mimikri/etc/policy.json \
  --postgres-url "$DATABASE_URL" \
  --dashboard 8080 \
  --scope-id "$SCOPE_ID" \
  --autonomous \
  --swarm \
  --nats-url "$NATS_URL" \
  --max-tokens 50000
```

The systemd unit (§5.2) provides secrets via `EnvironmentFile=-/run/mimikri/secrets.env` and the `ConditionPathExists=/run/mimikri/secrets.env` guard, so the unit stays inactive (no crash loop) until secrets are unlocked.

```bash
sudo install -o root -g mimikri -m 0750 run-coordinator.sh /opt/mimikri/bin/
```

### 5.2 systemd unit

`/etc/systemd/system/redteam-coordinator.service`:

```ini
[Unit]
Description=Mimikri Coordinator
After=network-online.target tailscaled.service
Wants=network-online.target
PartOf=mimikri.target

[Service]
Type=simple
User=mimikri
Group=mimikri
WorkingDirectory=/opt/mimikri
ExecStart=/opt/mimikri/bin/run-coordinator.sh
Restart=on-failure
RestartSec=10
TimeoutStopSec=60s
KillSignal=SIGINT          # triggers kill-switch (destroys DO droplets)

# Sandboxing
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@mount @debug @cpu-emulation @keyring @obsolete @raw-io @reboot @swap @privileged
ReadWritePaths=/opt/mimikri/workspace /var/log/mimikri
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE

# Resource limits
MemoryMax=10G
MemoryHigh=8G
CPUWeight=200
TasksMax=512
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable redteam-coordinator
# Do NOT start yet — wait for Box2/Box3 + smoke test
```

---

## 6. Dashboard binding

The dashboard binds to `0.0.0.0:8080` by default. We restrict to `tailscale0`:

```bash
# Verify dashboard listener (post first start)
ss -ltnp | grep 8080
# Expected: 100.x.x.x:8080 only

sudo ufw allow in on tailscale0 to any port 8080 proto tcp comment 'dashboard via tailnet (cloudflared on localhost too)'
```

> [!IMPORTANT]
> Cloudflare Tunnel (see `07_DASHBOARD_PUBLIC_ACCESS.md`) connects to `http://localhost:8080`, not the tailnet IP. The dashboard MUST also listen on loopback. If `redteam_rust_core` doesn't expose this, run `cloudflared` on Box1 with `--url http://100.x.x.x:8080` instead.

Dashboard authentication token at `/opt/mimikri/workspace/logs/dashboard.token` — readable only by mimikri user. Operator retrieves via:
```bash
ssh opsec@mimikri-box1 'sudo -u mimikri cat /opt/mimikri/workspace/logs/dashboard.token'
```

---

## 7. Backups

Box1 does **not** host the Postgres primary (moved to Box2). Backups on Box1
are limited to workspace logs, local config, and OCI Object Storage cold archive.

### 7.1 Workspace logs + OCI Object Storage cold archive

Daily tarball of `/opt/mimikri/workspace/logs` and `/var/log/mimikri`:

`/usr/local/bin/box1-backup.sh`:
```bash
#!/usr/bin/env bash
set -euo pipefail

BACKUP_DIR=/var/backups/mimikri/daily
mkdir -p "$BACKUP_DIR"
DUMP="$BACKUP_DIR/box1-$(date +%F).tar.gz"

tar czf "$DUMP" -C / opt/mimikri/workspace/logs var/log/mimikri
chmod 600 "$DUMP"

# Retain 30 days locally
find "$BACKUP_DIR" -name 'box1-*.tar.gz' -mtime +30 -delete

# Replicate to Box3 via Tailscale rsync (passwordless, key-only)
rsync -az --delete "$BACKUP_DIR/" opsec@mimikri-box3:/var/backups/mimikri/box1/

# Encrypt one weekly snapshot for offline cold storage
if [[ $(date +%u) -eq 7 ]]; then
  age -R /opt/mimikri/etc/age-recipient.txt -o "$DUMP.age" "$DUMP"
  oci os object put --bucket-name mimikri-cold --file "$DUMP.age"
fi
```

`/etc/cron.d/box1-backup`:
```
0 3 * * * root /usr/local/bin/box1-backup.sh > /var/log/box1-backup.log 2>&1
```

### 7.2 Oracle-managed Block Volume Backup (paid tier, credit-funded)

Enable Oracle's volume-level snapshot service for Box1's boot volume + workspace volume. These snapshots are immutable, off-host, and survive a full ransomware compromise of the live VM.

> [!NOTE]
> Box1 no longer has a dedicated Postgres data volume (Postgres primary moved to Box2).
> Snapshots cover only the boot volume and workspace data.

Allocated from the $300 credit per `HYBRID §7` ($60/yr ≈ daily snapshots for 1 year).

```bash
# Oracle console: Storage → Block Volumes → <Box1 boot volume> → Backup Policies
#   Apply policy: Bronze (daily, 7d retention) OR Silver (daily + weekly, 90d retention)

# Or via CLI:
BOOT_VOL_ID=$(oci compute boot-volume list --availability-domain <AD> --compartment-id <root> --query 'data[?"display-name"==`mimikri-box1-boot`].id|[0]' --raw-output)

oci bv volume-backup-policy-assignment create \
  --asset-id "$BOOT_VOL_ID" \
  --policy-id <silver-policy-ocid>
```

Day-350 graduation step (covered in `09 §10`): export final weekly snapshot to operator local NAS, then unassign the policy. Snapshots remain accessible read-only during the suspend grace period.

```bash
# Binary verified + AppArmor enforcing
sudo aa-status | grep redteam_rust_core
# Expected: enforce mode

# Service config valid (do not start yet)
sudo systemd-analyze verify redteam-coordinator.service
```

---

## 8. Pitfalls

| Pitfall | Symptom | Fix |
|---|---|---|
| ARM64 vs x86 binary mismatch | `Exec format error` | Cross-compile with `--target aarch64-unknown-linux-musl` |
| Postgres listens 0.0.0.0 by default | UFW saves you but logs noisy | Set `listen_addresses` to specific IPs in postgresql.conf |
| pgaudit not loaded | No audit trail | `shared_preload_libraries = 'pgaudit'` requires restart |
| systemd `MemoryDenyWriteExecute` blocks JIT | Some Rust crates use JIT (rare) | Profile; relax only if necessary |
| Dashboard token leaked via `journalctl` | Token visible in logs | Service uses SCRUBBER (Sprint 9 H3); confirm `journalctl -u redteam-coordinator | grep token` redacts |
| Secrets not unlocked after reboot | `redteam-coordinator` inactive with `ConditionPathExists` failure | Operator runs `unlock-remote.sh box1` from workstation (`08_SECRETS_MANAGEMENT.md` §4.3) |

Proceed to `03_BOX2_AI_ENRICHMENT.md`.
