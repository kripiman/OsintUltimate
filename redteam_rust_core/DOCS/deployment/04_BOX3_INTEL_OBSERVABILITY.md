# 04 — Box3: Intel + Observability (Postgres Replica + CertStream + NVD + Loki/Grafana + Janitor)

**Role**: Postgres streaming replica, CertStream + NVD passive intel, Loki/Grafana observability, DigitalOcean droplet janitor cron.

**Prerequisites**: `01`, `05`, `08`, **Box2** reachable on tailnet (Box2 is the Postgres primary).

**Specs**: 4 OCPU ARM / 24GB RAM, always-free tier.

---

## 1. Service user + directories

```bash
sudo groupadd -r mimikri-intel
sudo useradd -r -g mimikri-intel -d /opt/mimikri-intel -s /sbin/nologin mimikri-intel

sudo install -d -o root -g mimikri-intel -m 0750 /opt/mimikri-intel
sudo install -d -o mimikri-intel -g mimikri-intel -m 0750 /opt/mimikri-intel/{bin,etc,workspace}
sudo install -d -o postgres -g postgres -m 0700 /var/lib/postgresql/16/replica
sudo install -d -o root -g adm -m 0750 /var/log/mimikri-intel
```

---

## 2. PostgreSQL streaming replica

**Box2** is primary (see `03_BOX2_COORDINATOR.md`). Box3 is hot standby — read-only failover target.

### 2.1 Install (same as Box1 §2)

```bash
# PGDG repo as in 02 §2
sudo apt install -y postgresql-16 postgresql-contrib-16
sudo systemctl stop postgresql
sudo rm -rf /var/lib/postgresql/16/main/*
```

### 2.2 Configure replica auth on Box1

On Box2:
```bash
sudo -u postgres psql -c "ALTER ROLE replicator WITH REPLICATION LOGIN PASSWORD '<from-vault>';"

# pg_hba already allows from Box3 tailnet IP (see 03 §2.3)
sudo systemctl reload postgresql
```

### 2.3 Base backup from Box1 → Box3

On Box3:
```bash
sudo -u postgres pg_basebackup \
  -h mimikri-box2 \
  -D /var/lib/postgresql/16/main \
  -U replicator \
  -W \
  -P \
  -X stream \
  -R \
  -C -S mimikri_box3_slot
# Enter replicator password when prompted (from Vault)

sudo chown -R postgres:postgres /var/lib/postgresql/16/main
```

`-R` creates `standby.signal` + writes connection info to `postgresql.auto.conf`. Box3 boots as hot standby.

### 2.4 postgresql.conf on Box3

```conf
listen_addresses = 'localhost,100.x.x.z'
port = 5432
hot_standby = on
hot_standby_feedback = on
primary_slot_name = 'mimikri_box3_slot'
primary_conninfo = 'host=mimikri-box2 port=5432 user=replicator password=<from-vault> sslmode=require application_name=mimikri-box3'
```

Recovery from Vault — wrap in a launcher that materializes `primary_conninfo` from `DATABASE_REPLICATION_PASSWORD` Vault secret at start.

### 2.5 Start replica + verify

```bash
sudo systemctl start postgresql

sudo -u postgres psql -c "SELECT pg_is_in_recovery();"
# Expected: t

# Check lag (on Box2)
ssh opsec@mimikri-box2 'sudo -u postgres psql -c "SELECT application_name, state, sync_state, write_lag, flush_lag, replay_lag FROM pg_stat_replication;"'
# Expected: mimikri-box3 / streaming / async / lag < 5s

sudo ufw allow in on tailscale0 to any port 5432 proto tcp comment 'replica read-only'
```

### 2.6 Failover procedure (drill)

If Box1 dies:
```bash
# On Box3
sudo -u postgres pg_ctl promote -D /var/lib/postgresql/16/main

# Verify
sudo -u postgres psql -c "SELECT pg_is_in_recovery();"
# Expected: f (now primary)

# Update Box1 + workers to point to mimikri-box3
ssh opsec@mimikri-box1 'sudo systemctl restart redteam-enrichment'
```

Drill quarterly per `00_OVERVIEW.md` §6.

---

## 3. CertStream daemon

Passive monitoring of certificate transparency logs. Looks for new TLS certs matching `CERTSTREAM_KEYWORDS` (defined per scope).

```bash
# CertStream is part of redteam_rust_core
# Run as a dedicated mode
```

`/opt/mimikri-intel/bin/run-certstream.sh`:
```bash
#!/usr/bin/env bash
set -euo pipefail

set -a
. /opt/mimikri-intel/etc/runtime.env
set +a
# Secrets pre-loaded into /run/mimikri/secrets.env by operator (see 08_SECRETS_MANAGEMENT.md §4.3)
. /run/mimikri/secrets.env

exec /usr/local/bin/redteam_rust_core \
  --certstream-daemon \
  --certstream-keywords "$CERTSTREAM_KEYWORDS" \
  --postgres-url "$DATABASE_URL" \
  --nats-url "$NATS_URL"
# Note: DATABASE_URL points to Box2 primary (or Box3 itself if promoted)
```

`/etc/systemd/system/redteam-certstream.service`:
```ini
[Unit]
Description=Mimikri CertStream Monitor
After=network-online.target tailscaled.service
Wants=network-online.target

[Service]
Type=simple
User=mimikri-intel
Group=mimikri-intel
ExecStart=/opt/mimikri-intel/bin/run-certstream.sh
Restart=on-failure
RestartSec=10

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
RestrictSUIDSGID=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@mount @debug @cpu-emulation @keyring @obsolete @raw-io @reboot @swap @privileged

MemoryMax=512M
CPUWeight=50

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable redteam-certstream
```

---

## 4. NVD CVE monitor

Polls NVD API every 6h for new CVEs, correlates with discovered service banners.

`redteam_rust_core` runs this as part of the worker. On Box3 use `--worker --cve-correlation-only` (Sprint 10 flag) **or** invoke the standalone `cve_cache` updater:

`/etc/cron.d/nvd-update`:
```
0 */6 * * * mimikri-intel /opt/mimikri-intel/bin/nvd-update.sh > /var/log/mimikri-intel/nvd.log 2>&1
```

`/opt/mimikri-intel/bin/nvd-update.sh`:
```bash
#!/usr/bin/env bash
set -euo pipefail
# Secrets pre-loaded into /run/mimikri/secrets.env by operator (see 08_SECRETS_MANAGEMENT.md §4.3)
. /run/mimikri/secrets.env
export NVD_API_KEY
export DATABASE_URL

/usr/local/bin/redteam_rust_core --update-cve-cache
```

---

## 5. Droplet janitor — destroys DO leftovers > TTL

If Box1 crashes or kill-switch fails to clean up, this ensures no orphan billing.

`/etc/cron.d/droplet-janitor`:
```
*/15 * * * * mimikri-intel /opt/mimikri-intel/bin/droplet-janitor.sh > /var/log/mimikri-intel/janitor.log 2>&1
```

`/opt/mimikri-intel/bin/droplet-janitor.sh`:
```bash
#!/usr/bin/env bash
set -euo pipefail

# Fetch DO token from Vault
# Secrets pre-loaded into /run/mimikri/secrets.env by operator (see 08_SECRETS_MANAGEMENT.md §4.3)
. /run/mimikri/secrets.env

NOW=$(date +%s)
TTL_SECONDS=21600    # 6 hours

# List all droplets tagged purpose:redteam-ephemeral
DROPLETS=$(curl -s -H "Authorization: Bearer $DO_TOKEN" \
  "https://api.digitalocean.com/v2/droplets?tag_name=purpose:redteam-ephemeral&per_page=200")

echo "$DROPLETS" | jq -c '.droplets[] | {id, created_at, tags}' | while read -r d; do
  ID=$(echo "$d" | jq -r .id)
  CREATED=$(echo "$d" | jq -r .created_at)
  CREATED_TS=$(date -d "$CREATED" +%s)
  AGE=$((NOW - CREATED_TS))

  if (( AGE > TTL_SECONDS )); then
    logger -t droplet-janitor "DESTROYING droplet $ID (age ${AGE}s > ${TTL_SECONDS}s)"
    curl -sX DELETE -H "Authorization: Bearer $DO_TOKEN" \
      "https://api.digitalocean.com/v2/droplets/$ID" || true
  fi
done
```

```bash
sudo install -o root -g mimikri-intel -m 0750 droplet-janitor.sh /opt/mimikri-intel/bin/
```

---

## 6. Loki + Grafana + Tempo (observability stack)

### 6.1 Install via tarballs (no Docker on Oracle free tier ARM)

```bash
LOKI_VERSION=3.0.0
GRAFANA_VERSION=11.1.0
TEMPO_VERSION=2.5.0

# Loki
curl -fsSL -o /tmp/loki.zip https://github.com/grafana/loki/releases/download/v${LOKI_VERSION}/loki-linux-arm64.zip
sudo unzip /tmp/loki.zip -d /usr/local/bin
sudo mv /usr/local/bin/loki-linux-arm64 /usr/local/bin/loki
sudo chmod 755 /usr/local/bin/loki

# Tempo
curl -fsSL https://github.com/grafana/tempo/releases/download/v${TEMPO_VERSION}/tempo_${TEMPO_VERSION}_linux_arm64.tar.gz \
  | sudo tar -xzC /usr/local/bin tempo

# Grafana (deb repo)
sudo apt install -y software-properties-common
sudo wget -qO /usr/share/keyrings/grafana.key https://apt.grafana.com/gpg.key
echo "deb [signed-by=/usr/share/keyrings/grafana.key] https://apt.grafana.com stable main" \
  | sudo tee /etc/apt/sources.list.d/grafana.list
sudo apt update && sudo apt install -y grafana
```

### 6.2 Config

`/etc/loki/loki.yaml`:
```yaml
auth_enabled: true

server:
  http_listen_address: 100.x.x.z       # tailscale0
  http_listen_port: 3100
  grpc_listen_address: 100.x.x.z
  grpc_listen_port: 9095
  log_level: info

common:
  path_prefix: /var/lib/loki
  storage:
    filesystem:
      chunks_directory: /var/lib/loki/chunks
      rules_directory: /var/lib/loki/rules
  replication_factor: 1
  ring:
    kvstore:
      store: inmemory

schema_config:
  configs:
    - from: 2024-01-01
      store: tsdb
      object_store: filesystem
      schema: v13
      index:
        prefix: index_
        period: 24h

limits_config:
  retention_period: 90d                # cap log retention
  max_query_length: 12000h
  ingestion_rate_mb: 8
  ingestion_burst_size_mb: 16

ruler:
  storage:
    type: local
    local:
      directory: /var/lib/loki/rules
  rule_path: /var/lib/loki/rules-temp
  alertmanager_url: http://localhost:9093
```

`/etc/grafana/grafana.ini` — restrict to tailnet + enforce HTTPS via tailnet TLS:
```ini
[server]
http_addr = 100.x.x.z
http_port = 3000
domain = mimikri-box3
root_url = http://mimikri-box3:3000/
protocol = http
enforce_domain = true

[security]
admin_user = mimikri-admin
admin_password = $__file{/etc/grafana/admin-pw}
disable_initial_admin_creation = true
disable_gravatar = true
cookie_secure = true
cookie_samesite = strict
content_security_policy = true
strict_transport_security = true
allow_embedding = false

[auth.anonymous]
enabled = false

[users]
auto_assign_org = true
auto_assign_org_role = Viewer
default_theme = dark
```

> [!IMPORTANT]
> Grafana is **not** exposed publicly. Operator reaches it via Tailscale (`http://mimikri-box3:3000`). No Cloudflare Tunnel for Grafana.

### 6.3 Tempo

`/etc/tempo/tempo.yaml`:
```yaml
server:
  http_listen_port: 3200
  grpc_listen_port: 9096

distributor:
  receivers:
    otlp:
      protocols:
        grpc:
          endpoint: 100.x.x.z:4317
        http:
          endpoint: 100.x.x.z:4318

storage:
  trace:
    backend: local
    local:
      path: /var/lib/tempo/traces

compactor:
  compaction:
    block_retention: 168h           # 7 days
```

### 6.4 UFW

```bash
sudo ufw allow in on tailscale0 to any port 3100 proto tcp comment 'loki push'
sudo ufw allow in on tailscale0 to any port 3000 proto tcp comment 'grafana ui'
sudo ufw allow in on tailscale0 to any port 4317 proto tcp comment 'otel grpc'
sudo ufw allow in on tailscale0 to any port 4318 proto tcp comment 'otel http'
sudo ufw reload
```

### 6.5 systemd units

Standard pattern (User=loki/tempo/grafana, hardened sandboxing as in §2.5 of `02_BOX1`). Skipped here for brevity — apply the same template.

```bash
sudo systemctl enable --now loki tempo grafana-server
```

### 6.6 Promtail on each box (log shipping)

On Box1, Box2, Box3:

```bash
PROMTAIL_VERSION=3.0.0
curl -fsSL -o /tmp/promtail.zip https://github.com/grafana/loki/releases/download/v${PROMTAIL_VERSION}/promtail-linux-arm64.zip
sudo unzip /tmp/promtail.zip -d /usr/local/bin
sudo mv /usr/local/bin/promtail-linux-arm64 /usr/local/bin/promtail
sudo chmod 755 /usr/local/bin/promtail
```

`/etc/promtail/promtail.yaml`:
```yaml
server:
  http_listen_port: 9080
  grpc_listen_port: 0

positions:
  filename: /var/lib/promtail/positions.yaml

clients:
  - url: http://mimikri-box3:3100/loki/api/v1/push
    tenant_id: mimikri
    basic_auth:
      username: mimikri
      password: ${LOKI_PASSWORD}

scrape_configs:
  - job_name: journal
    journal:
      max_age: 12h
      labels:
        job: systemd-journal
        host: ${HOSTNAME}
    relabel_configs:
      - source_labels: ['__journal__systemd_unit']
        target_label: unit
      - source_labels: ['__journal_priority_keyword']
        target_label: level

  - job_name: auditd
    static_configs:
      - targets: [localhost]
        labels:
          job: auditd
          host: ${HOSTNAME}
          __path__: /var/log/audit/audit.log

  - job_name: ufw
    static_configs:
      - targets: [localhost]
        labels:
          job: ufw
          host: ${HOSTNAME}
          __path__: /var/log/ufw.log
```

```bash
sudo install -d -o promtail -g promtail -m 0750 /var/lib/promtail
# systemd unit with same sandboxing template
sudo systemctl enable --now promtail
```

### 6.7 Grafana dashboards

Provision via `/etc/grafana/provisioning/dashboards/mimikri.yaml`:

```yaml
apiVersion: 1
providers:
  - name: mimikri
    folder: Mimikri
    type: file
    options:
      path: /var/lib/grafana/dashboards/mimikri
```

Pre-built dashboards to commit to `redteam_rust_core/infrastructure/grafana/`:
- `01-scan-throughput.json` — scans/min, findings/min, queue depth
- `02-error-rates.json` — errors by service, severity histogram
- `03-droplet-fleet.json` — active DO droplets, TTL distribution, $ spend
- `04-auditd-alerts.json` — auditd violations, fail2ban bans
- `05-postgres-replication.json` — lag, WAL throughput, slot health
- `06-ollama.json` — inference latency, model load events
- `08-credit-exhaustion.json` — credit burn rate (Box1 student credit only, Box2/Box3 unaffected)

### 6.8 Alert rules

`/etc/loki/rules/mimikri.yaml`:

```yaml
groups:
  - name: mimikri-critical
    interval: 1m
    rules:
      - alert: PostgresReplicationLag
        expr: |
          rate({job="postgresql", host="mimikri-box1"} |= "replication lag" |~ "[0-9]+s" [5m])
            > bool 5
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Postgres replication lag > 5s"

      - alert: DropletJanitorFailed
        expr: |
          count_over_time({job="systemd-journal", unit="cron.service"} |= "droplet-janitor" |= "error" [30m]) > 0
        labels:
          severity: critical
        annotations:
          summary: "Droplet janitor errors in last 30min"

      - alert: AuditdHighSeverity
        expr: |
          count_over_time({job="auditd"} |~ "(?i)(failed login|unauthorized)" [5m]) > 5
        labels:
          severity: warning
        annotations:
          summary: "5+ auditd alerts in 5min"

      - alert: KillSwitchFired
        expr: |
          count_over_time({unit="redteam-coordinator.service"} |= "destroy_all_ephemeral_droplets" [10m]) > 0
        labels:
          severity: info
        annotations:
          summary: "Kill-switch executed"
```

### 6.9 Oracle Logging Analytics Connector (Optional, paid tier)

For redundancy in log ingestion, configure the Oracle Cloud Infrastructure (OCI) Logging Analytics service. This parallel log delivery pipeline ensures that even if Box3 (the primary Loki host) is compromised or inaccessible, security logs are safely stored in Oracle-managed vaults.

Allocated from the $300 credit per `HYBRID §7` ($40/yr ≈ 90 days retention for 1 year).

1. **Install OCI Management Agent**:
   Download and install the agent on Box1, Box2, Box3 to stream files to Logging Analytics.
   ```bash
   # Download the management agent installer from the OCI Console (Management Agent > Downloads)
   sudo rpm -ivh oracle-management-agent-*.rpm # For Oracle Linux/RHEL
   # Or install on Ubuntu/Debian:
   sudo dpkg -i oracle-management-agent-*.deb

   # Configure the agent using response file containing your install key:
   sudo /opt/oracle/mgmt_agent/bin/setupAgent.sh /opt/oracle/mgmt_agent/agent_install_key.rsp
   ```

2. **Define Log Sources**:
   In the OCI Console (Logging Analytics > Administration > Sources), create sources matching your log formats:
   - `mimikri-auditd`: points to `/var/log/audit/audit.log`
   - `mimikri-ufw`: points to `/var/log/ufw.log`
   - `mimikri-systemd`: connects to journald logs via sys-log integration

3. **Define Log Groups**:
   Associate these sources with a dedicated log group (`mimikri-security-logs-group`) for access control and isolation.

Day-350 graduation step (covered in `09 §10`): Migrate all custom parsing rules from OCI Logging Analytics to Loki (where they should be committed under `infrastructure/loki-parsers/`), then delete the OCI log group and stop the management agent services.

---

## 7. Verification

```bash
# Replica streaming
sudo -u postgres psql -c "SELECT pg_is_in_recovery();"
# t

# CertStream daemon running
sudo systemctl is-active redteam-certstream

# Janitor cron executes
sudo grep -i "droplet-janitor" /var/log/syslog | tail -5

# Loki receiving
curl -G http://mimikri-box3:3100/loki/api/v1/query --data-urlencode 'query={job="systemd-journal"}' --data-urlencode "limit=1"

# Grafana up
curl -s http://mimikri-box3:3000/api/health | jq

# Promtail on all 3 boxes
for b in box1 box2 box3; do
  ssh opsec@mimikri-$b 'systemctl is-active promtail'
done
```

---

## 8. Pitfalls

| Pitfall | Symptom | Fix |
|---|---|---|
| Replication slot fills disk on Box1 | `WAL files accumulating` | Verify Box3 connected: `pg_replication_slots.active = t` |
| Janitor authenticated but lists 0 droplets | DO tag mismatch | `purpose:redteam-ephemeral` not `purpose=redteam-ephemeral` in DO tag syntax |
| Grafana admin password committed | Secret leak | Use `$__file{}` indirection (above), never inline |
| Loki ingestion rate exceeded | Logs lost | Increase `ingestion_rate_mb` or shorten retention |
| Tempo OTLP port collision | Box1 also wants 4317 | OTEL endpoint always points to Box3 — Box1 doesn't listen for OTLP |
| CertStream uses too much memory under high TLS volume | OOM kill | Set `MemoryMax=512M` per service unit + bloom filter pre-filter in code |
| Replica diverges after Box1 promote drill | Re-init required | `pg_basebackup` from new primary |

Proceed to `06_DO_EPHEMERAL_WORKERS.md`.
