# 02 — Box1: AI Enrichment Pipeline (Ollama + Router + BloodHound) ⚠️ Sacrificable

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

## 2. PostgreSQL 16 installation

```bash
# Official PGDG repo (Ubuntu 22.04 has 14 by default; we want 16)
sudo apt install -y curl ca-certificates
sudo install -d /usr/share/postgresql-common/pgdg
sudo curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc \
  -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc
echo "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] \
  https://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" \
  | sudo tee /etc/apt/sources.list.d/pgdg.list
sudo apt update
sudo apt install -y postgresql-16 postgresql-contrib-16 postgresql-16-pgaudit
```

### 2.1 Cluster on encrypted block volume

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

### 2.2 PostgreSQL configuration

`/etc/postgresql/16/main/postgresql.conf` — key settings only:

```conf
# Network
listen_addresses = 'localhost,100.x.x.x'    # tailscale0 IP
port = 5432

# Resources (4c/24GB box, dedicate ~8GB to postgres)
shared_buffers = 6GB
effective_cache_size = 16GB
work_mem = 16MB
maintenance_work_mem = 1GB
max_connections = 100

# WAL + replication (Box1→Box3)
wal_level = replica
max_wal_senders = 5
max_replication_slots = 5
wal_keep_size = 2GB
archive_mode = on
archive_command = 'test ! -f /var/backups/postgres/wal/%f && cp %p /var/backups/postgres/wal/%f'

# Logging
log_destination = 'stderr,syslog'
syslog_facility = 'LOCAL0'
logging_collector = on
log_directory = '/var/log/postgresql'
log_filename = 'postgresql-%Y-%m-%d_%H%M%S.log'
log_rotation_age = 1d
log_min_duration_statement = 250ms          # log slow queries
log_statement = 'mod'                       # log all DDL/DML
log_connections = on
log_disconnections = on
log_line_prefix = '%t [%p] %q%u@%d/%a '

# pgaudit (full audit trail)
shared_preload_libraries = 'pgaudit'
pgaudit.log = 'write, ddl, role'
pgaudit.log_catalog = off
pgaudit.log_parameter = on
pgaudit.log_relation = on

# SSL — mandatory for non-loopback
ssl = on
ssl_cert_file = '/etc/postgresql/16/main/server.crt'
ssl_key_file = '/etc/postgresql/16/main/server.key'
ssl_min_protocol_version = 'TLSv1.3'
password_encryption = scram-sha-256
```

### 2.3 pg_hba.conf — strict access

`/etc/postgresql/16/main/pg_hba.conf`:

```
# TYPE   DATABASE   USER         ADDRESS              METHOD       OPTIONS

# Local maintenance (peer-auth as postgres user only)
local    all        postgres                          peer
local    all        all                               scram-sha-256

# Tailnet — coordinators and workers connect over TLS+SCRAM
hostssl  redteam    mimikri      100.64.0.0/10        scram-sha-256
hostssl  redteam    mimikri_ro   100.64.0.0/10        scram-sha-256

# Replication to Box3 (over Tailscale)
hostssl  replication replicator  100.x.x.z/32         scram-sha-256

# Everyone else: deny
host     all        all          0.0.0.0/0            reject
host     all        all          ::/0                 reject
```

### 2.4 Generate TLS cert (self-signed, replaced by Tailscale-internal CA optionally)

```bash
sudo -u postgres openssl req -new -x509 -days 365 -nodes -text \
  -out /etc/postgresql/16/main/server.crt \
  -keyout /etc/postgresql/16/main/server.key \
  -subj "/CN=mimikri-box1.tail-XXXX.ts.net"
sudo chmod 600 /etc/postgresql/16/main/server.key
sudo chown postgres:postgres /etc/postgresql/16/main/server.{crt,key}
```

### 2.5 Apply schema

```bash
# Restart Postgres with new config
sudo systemctl restart postgresql

# Create role + DB
sudo -u postgres psql <<EOF
CREATE ROLE mimikri WITH LOGIN PASSWORD 'TEMP_PLACEHOLDER';   -- rotated immediately
CREATE ROLE mimikri_ro WITH LOGIN PASSWORD 'TEMP_PLACEHOLDER';
CREATE ROLE replicator WITH REPLICATION LOGIN PASSWORD 'TEMP_PLACEHOLDER';
CREATE DATABASE redteam OWNER mimikri;
\c redteam
GRANT CONNECT ON DATABASE redteam TO mimikri_ro;
GRANT USAGE ON SCHEMA public TO mimikri_ro;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO mimikri_ro;
EOF

# Load schema from repo
psql "postgres://mimikri@localhost/redteam" -f /path/to/redteam_rust_core/schema.sql

# Rotate passwords via 08_SECRETS_MANAGEMENT.md §4 procedure
```

### 2.6 UFW rules for postgres

```bash
sudo ufw allow in on tailscale0 to any port 5432 proto tcp comment 'postgres on tailnet'
# Block on all other interfaces (default-deny already does this)
sudo ufw reload
```

---

## 3. NATS mesh hub

NATS is the inter-agent message bus for swarm V4.0. Box1 runs the hub; Box3 runs a secondary.

### 3.1 Install

```bash
NATS_VERSION=2.10.18
curl -fsSL https://github.com/nats-io/nats-server/releases/download/v${NATS_VERSION}/nats-server-v${NATS_VERSION}-linux-arm64.tar.gz | sudo tar -xzC /usr/local/bin --strip-components=1 nats-server-v${NATS_VERSION}-linux-arm64/nats-server
sudo chmod 755 /usr/local/bin/nats-server
sudo install -d -o nobody -g nogroup -m 0700 /var/lib/nats
```

### 3.2 Config

`/etc/nats/nats-server.conf`:

```
listen: 100.x.x.x:4222              # tailscale0 only
http: 100.x.x.x:8222                # monitoring (read-only)
server_name: mimikri-box1-nats
max_payload: 16MB
write_deadline: "10s"

# TLS — required for cross-tenancy mesh
tls {
  cert_file: "/etc/nats/server.crt"
  key_file: "/etc/nats/server.key"
  ca_file: "/etc/nats/ca.crt"
  verify_and_map: true
  cipher_suites: [
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256"
  ]
}

# JWT-based auth
operator: "/etc/nats/operator.jwt"
resolver: MEMORY
resolver_preload {
  ACC_REDTEAM: "<account JWT>"
}

# Cluster with Box3 secondary
cluster {
  name: mimikri-mesh
  listen: 100.x.x.x:6222
  authorization {
    user: cluster
    password: "$NATS_CLUSTER_PASS"
  }
  routes = [
    nats-route://cluster:$NATS_CLUSTER_PASS@mimikri-box3:6222
  ]
  tls {
    cert_file: "/etc/nats/cluster.crt"
    key_file:  "/etc/nats/cluster.key"
    ca_file:   "/etc/nats/ca.crt"
  }
}

jetstream {
  store_dir: "/var/lib/nats/jetstream"
  max_memory_store: 2GB
  max_file_store: 10GB
}

# Limits to prevent abuse
max_connections: 1024
max_subscriptions: 10000
ping_interval: "30s"
ping_max: 3
```

Generate NATS NKey/JWT credentials with `nsc` (https://docs.nats.io/using-nats/nats-tools/nsc). Operator/account/user setup out of scope here — see NATS official docs. Bundle the `.creds` content into `secrets.env.age` (per `08_SECRETS_MANAGEMENT.md`) as `NATS_OPERATOR_CREDS=...` and write it to disk on unlock.

### 3.3 Systemd service

`/etc/systemd/system/nats.service`:

```ini
[Unit]
Description=NATS server (mimikri mesh hub)
After=network-online.target tailscaled.service
Wants=network-online.target

[Service]
Type=simple
User=nobody
Group=nogroup
ExecStart=/usr/local/bin/nats-server -c /etc/nats/nats-server.conf
EnvironmentFile=/opt/mimikri/etc/nats.env
Restart=on-failure
RestartSec=5

NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ReadWritePaths=/var/lib/nats /var/log/nats
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@mount @debug @keyring @obsolete @privileged

[Install]
WantedBy=multi-user.target
```

```bash
sudo ufw allow in on tailscale0 to any port 4222 proto tcp comment 'nats client'
sudo ufw allow in on tailscale0 to any port 6222 proto tcp comment 'nats cluster'
sudo ufw allow in on tailscale0 from 100.x.x.x to any port 8222 proto tcp comment 'nats mon (Box3 only)'

sudo systemctl daemon-reload
sudo systemctl enable --now nats
```

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
NATS_URL=nats://mimikri-box1:4222
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
After=network-online.target postgresql.service nats.service tailscaled.service
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

Daily Postgres logical dump + WAL archive shipping to Box3.

`/etc/cron.d/postgres-backup`:
```
0 3 * * * postgres /usr/local/bin/postgres-backup.sh > /var/log/postgres-backup.log 2>&1
```

`/usr/local/bin/postgres-backup.sh`:
```bash
#!/usr/bin/env bash
set -euo pipefail

BACKUP_DIR=/var/backups/postgres/daily
mkdir -p "$BACKUP_DIR"
DUMP="$BACKUP_DIR/redteam-$(date +%F).dump.gz"

pg_dump -Fc redteam | gzip -9 > "$DUMP"
chmod 600 "$DUMP"

# Retain 30 days locally
find "$BACKUP_DIR" -name 'redteam-*.dump.gz' -mtime +30 -delete

# Replicate to Box3 via Tailscale rsync (passwordless, key-only)
rsync -az --delete "$BACKUP_DIR/" opsec@mimikri-box3:/var/backups/postgres/box1/

# Encrypt one weekly snapshot for offline cold storage
if [[ $(date +%u) -eq 7 ]]; then
  age -R /opt/mimikri/etc/age-recipient.txt -o "$DUMP.age" "$DUMP"
  # Stay within Box1 tenancy's 20GB free Object Storage allotment by day 350; older dumps rotate out via the
  # 30-day local retention above + bucket lifecycle policy. During credit window, paid tier ($80 in HYBRID §7
  # allocation) buys 250GB headroom for the same archive.
  oci os object put --bucket-name mimikri-cold --file "$DUMP.age"
fi
```

### 7.1 Oracle-managed Block Volume Backup (paid tier, credit-funded)

Independent of the pg_dump logical backup above, enable Oracle's volume-level snapshot service for Box1's boot volume + Postgres data volume. These snapshots are immutable, off-host, and survive a full ransomware compromise of the live VM.

Allocated from the $300 credit per `HYBRID §7` ($60/yr ≈ daily snapshots for 1 year).

```bash
# Oracle console: Storage → Block Volumes → <Box1 boot volume> → Backup Policies
#   Apply policy: Bronze (daily, 7d retention) OR Silver (daily + weekly, 90d retention)
# Repeat for Postgres data volume.

# Or via CLI:
BOOT_VOL_ID=$(oci compute boot-volume list --availability-domain <AD> --compartment-id <root> --query 'data[?"display-name"==`mimikri-box1-boot`].id|[0]' --raw-output)

oci bv volume-backup-policy-assignment create \
  --asset-id "$BOOT_VOL_ID" \
  --policy-id <silver-policy-ocid>
```

Day-350 graduation step (covered in `09 §10`): export final weekly snapshot to operator local NAS, then unassign the policy. Snapshots remain accessible read-only during the suspend grace period.

```bash
# Postgres listening only on tailscale0 + localhost
ss -ltnp | grep :5432
# Expected: 127.0.0.1:5432 and 100.x.x.x:5432

# Schema loaded
psql -h mimikri-box1 -U mimikri redteam -c '\dt'
# Expected: scans, targets, findings, workers, scan_queue, ... tables

# NATS reachable
nats-cli -s nats://mimikri-box1:4222 -creds ~/operator.creds rtt
# Expected: roundtrip < 5ms

# Binary verified + AppArmor enforcing
sudo aa-status | grep redteam_rust_core
# Expected: enforce mode

# Service config valid (do not start yet)
sudo systemd-analyze verify redteam-coordinator.service
```

---

## 9. Pitfalls

| Pitfall | Symptom | Fix |
|---|---|---|
| ARM64 vs x86 binary mismatch | `Exec format error` | Cross-compile with `--target aarch64-unknown-linux-musl` |
| Postgres listens 0.0.0.0 by default | UFW saves you but logs noisy | Set `listen_addresses` to specific IPs in postgresql.conf |
| pgaudit not loaded | No audit trail | `shared_preload_libraries = 'pgaudit'` requires restart |
| systemd `MemoryDenyWriteExecute` blocks JIT | Some Rust crates use JIT (rare) | Profile; relax only if necessary |
| Dashboard token leaked via `journalctl` | Token visible in logs | Service uses SCRUBBER (Sprint 9 H3); confirm `journalctl -u redteam-coordinator | grep token` redacts |
| Secrets not unlocked after reboot | `redteam-coordinator` inactive with `ConditionPathExists` failure | Operator runs `unlock-remote.sh box1` from workstation (`08_SECRETS_MANAGEMENT.md` §4.3) |

Proceed to `03_BOX2_AI_ENRICHMENT.md`.
