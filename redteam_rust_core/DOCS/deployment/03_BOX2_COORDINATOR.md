# 03 — Box2: Coordinator (Postgres + Dashboard + NATS Hub) ✅ Permanent

**Role**: Primary control plane. Hosts Postgres queue + findings store, NATS mesh hub, dashboard, sink aggregator, DO spawn controller. Secrets unlocked from operator workstation via `age`/YubiKey into tmpfs at `/run/mimikri/secrets.env`.

> [!IMPORTANT]
> Box2 is the **permanent brain** of the system. It runs on a personal Oracle account (not tied to any university email). Box1 (student account) is intentionally sacrificable. All critical services (Postgres primary, NATS, secrets, Dashboard) live here.

**Prerequisites**: `01_BASE_HARDENING.md`, `05_TAILSCALE_MESH.md`, `08_SECRETS_MANAGEMENT.md` completed.

**Specs**: 4 OCPU ARM / 24GB RAM, 200GB block storage, personal Oracle always-free tenancy (no paid services, no credit dependency).

---

## 1. Service user + directory

```bash
sudo groupadd -r mimikri-ai
sudo useradd -r -g mimikri-ai -d /opt/mimikri-ai -s /sbin/nologin -c "Mimikri AI" mimikri-ai

sudo install -d -o root -g mimikri-ai -m 0750 /opt/mimikri-ai
sudo install -d -o mimikri-ai -g mimikri-ai -m 0750 /opt/mimikri-ai/{bin,etc,workspace,workspace/logs}
sudo install -d -o mimikri-ai -g mimikri-ai -m 0755 /var/log/mimikri-ai
```

---

## 2. Ollama installation

### 2.1 Install (ARM64 native)

```bash
curl -fsSL https://ollama.com/install.sh | sh

# Verify ARM64 binary
file /usr/local/bin/ollama
# Expected: ELF 64-bit LSB executable, ARM aarch64
```

### 2.2 Bind to tailscale0 + harden

`/etc/systemd/system/ollama.service.d/override.conf`:

```ini
[Service]
Environment="OLLAMA_HOST=100.x.x.x:11434"
Environment="OLLAMA_MODELS=/var/lib/ollama/models"
Environment="OLLAMA_KEEP_ALIVE=15m"
Environment="OLLAMA_NUM_PARALLEL=2"
Environment="OLLAMA_MAX_LOADED_MODELS=1"
Environment="OLLAMA_FLASH_ATTENTION=1"
Environment="OLLAMA_NOPRUNE=true"

# Sandboxing
User=ollama
Group=ollama
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
RestrictRealtime=yes
RestrictSUIDSGID=yes
ReadWritePaths=/var/lib/ollama /var/log/ollama
SystemCallArchitectures=native

# Resource limits — Ollama is the heaviest service on this box
MemoryMax=18G
MemoryHigh=16G
CPUWeight=300
TasksMax=256
LimitNOFILE=65536
```

```bash
sudo mkdir -p /var/lib/ollama/models /var/log/ollama
sudo chown -R ollama:ollama /var/lib/ollama /var/log/ollama
sudo systemctl daemon-reload
sudo systemctl enable --now ollama
```

### 2.3 UFW

```bash
sudo ufw allow in on tailscale0 from 100.x.x.x to any port 11434 proto tcp comment 'ollama from Box1'
sudo ufw allow in on tailscale0 from 100.x.x.z to any port 11434 proto tcp comment 'ollama from Box3'
sudo ufw reload
```

### 2.4 Pull the production model

**Primary model**: `qwen2.5:14b-instruct-q4_K_M` (Alibaba Qwen 2.5, 14B parameters, 4-bit K-quant medium).

Rationale for this exact choice on a 4 OCPU / 24GB ARM box:
- 9GB resident — leaves 13GB for OS, enrichment worker, NATS client, and burst headroom.
- 4-6 tokens/sec on ARM Ampere CPU — sufficient for batch enrichment (findings are processed asynchronously, not on a human-blocking path).
- Strong instruction-following + reasoning at the 14B class — outperforms 8B Llama for vulnerability classification and exploit reasoning.
- Single model strategy aligns with `OLLAMA_MAX_LOADED_MODELS=1` in the systemd override — only one resident at a time, no thrashing.

**Embedder**: `nomic-embed-text` (0.3GB) — required by the findings similarity engine (`bk_tree.rs`) and dedup pipeline.

Nothing else is in scope for this deployment. If a future workload genuinely demands a different model (e.g. a coder-tuned variant for payload generation), benchmark in staging first and update this section — do not stack additional models in production.

```bash
sudo -u ollama ollama pull qwen2.5:14b-instruct-q4_K_M
sudo -u ollama ollama pull nomic-embed-text

# Verify
sudo -u ollama ollama list
# Expected: exactly 2 models
```

Total disk: ~9.3GB. Peak resident during inference: ~10GB (LLM loaded + embedder warm).

### 2.5 Pre-warm + test

```bash
curl -s http://mimikri-box2:11434/api/generate -d '{
  "model": "qwen2.5:14b-instruct-q4_K_M",
  "prompt": "Classify this finding: SQL injection in /api/users",
  "stream": false,
  "options": {"temperature": 0.2}
}' | jq .response
```

Expected first run: 10-30s (model load), subsequent ~3-5s for 100 tokens.

---

## 3. Worker mode for AI tasks

Box2 runs `redteam_rust_core --worker` but with a profile that only pulls **AI-enrichment** jobs from `scan_queue`, not active scan jobs. Implementation: Box2 sets `WORKER_PROFILE=ai` env var, the worker filters jobs by `priority` or a future `category` column.

> [!NOTE]
> The current `scan_queue` schema does not have a worker_profile column. Sprint 10 work item: add `worker_profile VARCHAR DEFAULT 'scan'` column. Interim: dedicate Box2 to non-scan tasks by NOT setting `--worker` and instead running enrichment via a separate binary or by relying on the swarm orchestrator's `--swarm` mode to assign roles. For now, Box2 runs the secondary swarm agent.

### 3.1 Launcher

`/opt/mimikri-ai/bin/run-enrichment.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

set -a
. /opt/mimikri-ai/etc/runtime.env
set +a

# Secrets already in /run/mimikri/secrets.env (tmpfs, unlocked from operator workstation via age-YubiKey).
# systemd's EnvironmentFile=-/run/mimikri/secrets.env exposes them as env vars.

[[ -z "${DATABASE_URL:-}" ]] && { echo "FATAL: no DATABASE_URL — run unlock-remote.sh box2 mimikri-ai" >&2; exit 1; }

exec /usr/local/bin/redteam_rust_core \
  --worker \
  --postgres-url "$DATABASE_URL" \
  --node-id mimikri-box2-ai \
  --concurrency 4 \
  --ollama-url http://localhost:11434 \
  --nats-url "$NATS_URL"
```

`/opt/mimikri-ai/etc/runtime.env`:
```env
RUST_LOG=info,sqlx=warn
OTEL_ENDPOINT=http://mimikri-box3:4317
NATS_URL=nats://mimikri-box1:4222
OLLAMA_URL=http://localhost:11434
```

### 3.2 systemd

`/etc/systemd/system/redteam-enrichment.service`:

```ini
[Unit]
Description=Mimikri AI Enrichment Worker
After=network-online.target ollama.service tailscaled.service
Wants=network-online.target

[Service]
Type=simple
User=mimikri-ai
Group=mimikri-ai
WorkingDirectory=/opt/mimikri-ai
ExecStart=/opt/mimikri-ai/bin/run-enrichment.sh
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
RestrictRealtime=yes
RestrictSUIDSGID=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@mount @debug @cpu-emulation @keyring @obsolete @raw-io @reboot @swap @privileged
ReadWritePaths=/opt/mimikri-ai/workspace /var/log/mimikri-ai

MemoryMax=4G
CPUWeight=100

[Install]
WantedBy=multi-user.target
```

---

## 4. BloodHound post-processor (optional, sovereign-flagged)

> [!NOTE]
> BloodHound graph processing is part of the `sovereign` feature. For default bug-bounty deployments, skip this section.

If you compiled with `--features sovereign`:

```bash
# Install Neo4j Community (BloodHound backend)
# ARM64 ARM build available from neo4j tarball
NEO4J_VERSION=5.21.0
sudo apt install -y openjdk-21-jdk-headless
curl -fsSL https://dist.neo4j.org/neo4j-community-${NEO4J_VERSION}-unix.tar.gz \
  | sudo tar -xzC /opt
sudo mv /opt/neo4j-community-${NEO4J_VERSION} /opt/neo4j
sudo chown -R mimikri-ai:mimikri-ai /opt/neo4j

# Bind to tailscale0 only
sudo tee -a /opt/neo4j/conf/neo4j.conf > /dev/null <<EOF
server.default_listen_address=100.x.x.x
dbms.security.auth_enabled=true
server.bolt.tls_level=REQUIRED
server.https.enabled=false
server.http.enabled=false
EOF

sudo ufw allow in on tailscale0 to any port 7687 proto tcp comment 'neo4j bolt'
```

`AdIngestor` config (covered by `--features sovereign`) writes nodes/edges directly via Bolt to `bolt://mimikri-box2:7687`.

---

## 5. Bug bounty auto-submit pipeline

Runs as a subsystem of `redteam-enrichment`. When findings reach severity ≥ High **and** `policy.json` declares the program in scope, the BountySink composes a report + submits via `H1_API_KEY`.

> [!IMPORTANT]
> Auto-submit can be disabled at runtime: `--no-auto-submit` flag (default on for first deploy). Verify policy decisions in Loki for 2 weeks before enabling.

Configuration via `runtime.env`:
```env
H1_HANDLE=your_handle
BB_AUTO_SUBMIT=false                # set to true after dry-run validation
BB_MIN_SEVERITY=High
BB_REQUIRE_OPERATOR_ACK=true        # operator must click "approve" in dashboard
```

The "approve" UI is the existing Dashboard ROI tab — operator sees pending submissions and clicks approve.

---

## 6. Model integrity verification

Ollama models are downloaded over HTTPS but Ollama does not pin a known-good SHA. Lock manifests:

```bash
# After pulling, snapshot manifests
sudo -u ollama bash -c 'cat /var/lib/ollama/models/manifests/registry.ollama.ai/library/qwen2.5/14b-instruct-q4_K_M | jq -r .layers[].digest | sort' \
  | sudo tee /opt/mimikri-ai/etc/model-baseline.sha256
```

Daily integrity check:

`/etc/systemd/system/model-integrity.service`:
```ini
[Unit]
Description=Verify Ollama model layer SHAs against baseline

[Service]
Type=oneshot
ExecStart=/opt/mimikri-ai/bin/verify-models.sh
StandardOutput=journal
```

`/opt/mimikri-ai/bin/verify-models.sh`:
```bash
#!/usr/bin/env bash
set -euo pipefail
BASELINE=/opt/mimikri-ai/etc/model-baseline.sha256
CURRENT=$(mktemp)
trap "rm -f $CURRENT" EXIT
sudo -u ollama bash -c 'cat /var/lib/ollama/models/manifests/registry.ollama.ai/library/qwen2.5/14b-instruct-q4_K_M | jq -r .layers[].digest | sort' > "$CURRENT"
if ! diff -q "$BASELINE" "$CURRENT" > /dev/null; then
  logger -t model-integrity "ALERT: model digest drift detected"
  exit 1
fi
```

```ini
# /etc/systemd/system/model-integrity.timer
[Unit]
Description=Daily model integrity check
[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true
[Install]
WantedBy=timers.target
```

```bash
sudo systemctl enable --now model-integrity.timer
```

---

## 7. Network isolation

Box2 outbound is locked down — Ollama doesn't need internet after models are pulled. **Disable outbound HTTPS to all but the tailnet + Oracle/DO APIs once steady state is reached.**

```bash
# After initial model pull, restrict egress
sudo ufw delete allow out 443/tcp 2>/dev/null || true

# Allow only the destinations Box2 actually needs
sudo ufw allow out to 100.64.0.0/10 comment 'tailnet'
sudo ufw allow out 53                comment 'DNS'
sudo ufw allow out 123/udp           comment 'NTP'
sudo ufw allow out 41641/udp         comment 'Tailscale'

# Box2 talks to HackerOne API (BB submit)
sudo ufw allow out to api.hackerone.com port 443 proto tcp comment 'H1 API'

sudo ufw reload
```

> [!WARNING]
> UFW `allow out to <hostname>` resolves once at rule-add time. If the upstream IP changes, the rule breaks. For high-stability, use iptables with `--match owner` for the `mimikri-ai` user, or run `cloudflared` as an egress proxy.

---

## 8. Verification

```bash
# Ollama on tailnet only
ss -ltnp | grep 11434
# Expected: 100.x.x.x:11434 (NOT 0.0.0.0 or 127.0.0.1 exposed beyond tailnet)

# Model loaded
curl -s http://mimikri-box2:11434/api/tags | jq '.models[].name'

# Enrichment worker can reach Box1 Postgres
sudo -u mimikri-ai psql -h mimikri-box1 -U mimikri redteam -c 'SELECT 1;'

# AppArmor enforce
sudo aa-status | grep ollama

# Model integrity baseline saved
test -f /opt/mimikri-ai/etc/model-baseline.sha256 && wc -l < /opt/mimikri-ai/etc/model-baseline.sha256
```

---

## 9. Pitfalls

| Pitfall | Symptom | Fix |
|---|---|---|
| Ollama OOM on 14b model | systemd OOM-kill | Lower `OLLAMA_NUM_PARALLEL` to 1, or raise `MemoryMax` toward 20G. Do not switch model class in production — re-benchmark via staging if 14B genuinely cannot fit. |
| Model pull over slow Oracle egress | Hours per model | Pre-download on workstation, scp to box, `ollama import` |
| First inference latency 30s | Cold start | `OLLAMA_KEEP_ALIVE=15m` keeps model warm |
| Concurrent inference serializes despite `OLLAMA_NUM_PARALLEL=2` | Both slots already busy | Single-model strategy means a 3rd concurrent caller waits. Acceptable for batch enrichment; if interactive UI needs lower latency, queue at the application layer (`router.rs`), not by raising parallelism. |
| Bug bounty auto-submit fires false positive | Reputation damage | Keep `BB_REQUIRE_OPERATOR_ACK=true` for first 90 days |
| Ollama listens on `0.0.0.0` default | Public exposure | Confirm `OLLAMA_HOST=100.x.x.x:11434` in systemd override |
| Model digest verification false alert | Ollama updated metadata | Re-baseline after each intentional `ollama pull` |

Proceed to `04_BOX3_INTEL_OBSERVABILITY.md`.
