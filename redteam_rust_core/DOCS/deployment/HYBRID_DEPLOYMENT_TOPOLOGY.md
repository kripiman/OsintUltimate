# Hybrid Deployment Topology — Oracle Control Plane + DigitalOcean Ephemeral Data Plane

**Status**: Architectural design — pre-implementation
**Author**: Auditor (Sprint 7.5 inter-sprint stabilization)
**Date**: 2026-05-20
**Related**: `stealth_opsec.md`, `multi_vps_deployment.original.md`, `infrastructure/digital_ocean.rs`

---

## 1. Motivation

Oracle Cloud Acceptable Use Policy prohibits port scanning, vulnerability scanning, brute-force, and any "intrusion attempt" originating from Oracle infrastructure. Running active red team plugins (nmap, exploitation/*, scanning/*) from Oracle VMs results in account termination and data loss.

DigitalOcean Acceptable Use Policy permits authorized penetration testing, with pre-notification recommended for sustained campaigns. DO is the appropriate substrate for outbound active probes.

This topology separates the **control plane** (orchestration, queueing, intel aggregation, AI enrichment, observability) on Oracle — which never originates packets to targets — from the **data plane** (active scanning) on DO ephemeral droplets that auto-destroy after job completion.

## 2. High-Level Topology

```
+------------------------------------------------------------------------+
|                        CONTROL PLANE (Oracle)                          |
|                                                                        |
|  +------------------+  +------------------+  +------------------+    |
|  |  Box1 (student!) |  |  Box2 (acct B)   |  |  Box3 (acct C)   |    |
|  |  4c/24GB ARM     |  |  4c/24GB ARM     |  |  4c/24GB ARM     |    |
|  |  [SACRIFICABLE]  |  |  [COORDINATOR]   |  |  [INTEL/OBS]     |    |
|  |                  |  |                  |  |                  |    |
|  | * AI/LLM router  |  | * Coordinator    |  | * Postgres replica|   |
|  | * compressor.rs  |  | * Dashboard 8080 |  | * CertStream     |    |
|  | * OllamaClient   |  | * Postgres prmy  |  | * NVD monitor    |    |
|  | * BloodHound     |  | * NATS hub       |  | * Loki/Grafana   |    |
|  | * Bug bounty sub |  | * Sink aggregator|  | * OTEL collector |    |
|  | * OCI paid svcs  |  | * secrets.env.age|  | * NATS secondary |    |
|  |   (ObjStorage,   |  |   (age/YubiKey)  |  | * Droplet janitor|    |
|  |   Backup,VSS,LA) |  | * interactsh poll|  |                  |    |
|  +--------+---------+  +--------+---------+  +--------+---------+    |
|           |                     |                     |              |
|           +------- Tailscale mesh (100.x.x.x) --------+              |
|                              |                |                      |
+------------------------------+----------------+----------------------+
                               |                |
                               |                | Tailscale poll :1337
               +---------------+------------+   |
               |  DO API (spawn/destroy)    |   |
               |  Tailscale auth-key        |   |
               +---------------+------------+   |
                               |                v
+------------------------------+-------+  +------------------------------+
|     DATA PLANE (DO ephemeral)        |  |  Box4 (Azure Africa OK)      |
|                                      |  |  1GB/2vCPU [INTERACTSH]      |
|  +--------+ +--------+               |  |                              |
|  |Droplet | |Droplet | ...           |  | * interactsh-server          |
|  | 1c/1GB | | 1c/1GB |              |  | * DNS  :53  (OOB callbacks)  |
|  |--worker| |--worker|              |  | * HTTP :80 / HTTPS :443      |
|  | TTL=6h | | TTL=6h |             |  | * SMTP :25 (email injection) |
|  | OOB    | | OOB    |             |  | * API  :1337 (tailnet only)  |
|  | payload| | payload|              |  | * NS -> oast.<your-domain>   |
|  +----+---+ +----+---+              |  +------------+-----------------+
+-------+----------+-----------------+               |
        |          |  OOB callbacks                  |
        v          v  ------------------>             |
  [ AUTHORIZED TARGETS ]                             |
  (nmap, interactsh payloads,  <--------------------+
   scanning/*, exploitation/*)
   Box4 captures DNS/HTTP/SMTP
   Box2 polls :1337 to correlate
```

## 2.1 Box Inventory

| Box | Provider / Region | Specs | Role | Persistence | Key Services |
|-----|-------------------|-------|------|-------------|--------------|
| Box1 | OCI (Always Free) | 4c / 24GB ARM | Sacrificable AI client | Persistent VM | Ollama client, BloodHound, Bug-bounty submitter, OCI paid services (ObjStorage, Backup, VSS, LA) |
| Box2 | OCI (Always Free) | 4c / 24GB ARM | Permanent coordinator | Persistent VM | Postgres primary, NATS hub, Ollama server (`qwen2.5:14b-instruct-q4_K_M`), Dashboard :8080, secrets vault (`age` / YubiKey) |
| Box3 | OCI (Always Free) | 4c / 24GB ARM | Intel / Observability | Persistent VM | Postgres replica, CertStream, NVD monitor, Loki/Grafana, OTEL collector, NATS secondary, droplet janitor |
| Box4 | Azure (Africa) | 1GB / 2vCPU | OOB Interactsh | Persistent VM | `interactsh-server`, DNS :53, HTTP/S, SMTP :25, API :1337 (tailnet only) |
| DO Droplets | DigitalOcean | 1c / 1GB (typical) | Ephemeral worker | **TTL ≤ 6h** | Active scan worker (nmap, exploitation, scanning plugins), OOB payload delivery |

> [!NOTE]
> DO droplets are **not** pre-provisioned inventory. They are spawned on-demand via the DO API by the janitor (`infrastructure/digital_ocean.rs`) and destroyed immediately after job completion. The `1c/1GB` spec is the default worker size; larger droplets (`2c/4GB`, `4c/8GB`) can be requested per-campaign via the `DO_DROPLET_SIZE` env var. All droplets join the Tailscale mesh before accepting NATS tasks.

## 3. Plane Responsibilities

### 3.1 Control Plane (Oracle — never touches targets)

> [!IMPORTANT]
> **Role assignment rationale**: Box1 uses a student email that the university may revoke after graduation. If Oracle invalidates the account, Box1 goes offline. The coordinator (Postgres primary, NATS hub, dashboard) must survive indefinitely — therefore it lives on Box2 (personal permanent account). Box1 is intentionally assigned *sacrificable* roles: AI enrichment and paid OCI services. Losing Box1 degrades enrichment quality but **never stops Bug Bounty operations**.

**Box1 — AI Enrichment + OCI Paid Services (student account ⚠️ — sacrificable)**
- **SACRIFICABLE**: University may revoke student email; Oracle may suspend this tenancy. Losing Box1 reduces enrichment quality but does not stop operations.
- `router.rs` classification stage (passive — operates on already-collected findings from Box2 Postgres)
- `compressor.rs` (`compress_finding_dense`, `compress_swarm_context`, `compress_target_lean`)
- Local LLM via OllamaClient (CPU inference on ARM, no GPU required)
- BloodHound graph post-processing (AdIngestor + `bloodhound.rs`)
- Bug bounty auto-submit sink (HackerOne API calls — outbound to API only, not to targets)
- Findings deduplication and correlation
- **OCI paid services (credit-funded)**: Object Storage 250GB (findings cold archive + worker binaries), Block Volume Backup of Box2 disk via Tailscale snapshot script, Vulnerability Scanning Service (all 3 boxes), Logging Analytics (log redundancy)

**Box2 — Coordinator (personal account ✅ — permanent)**
- **PERMANENT**: Personal email, always-free tier, no expiry risk. This is the system's brain.
- `RedTeamEngine` orchestrator (no scanning plugins enabled)
- PostgreSQL primary (queue table `scan_queue`, findings table, `mcp_stats`)
- Dashboard HTTP server on `:8080` (Tailscale-bound only, no public IP)
- NATS hub for swarm V4.0 inter-agent messaging
- Sink aggregator: receives findings from data plane workers, dispatches to JSONL/webhooks/Discord
- Secrets: `secrets.env.age` encrypted to operator's YubiKey-bound `age` identity. Decrypted into tmpfs at `/run/mimikri/secrets.env` only when the operator runs `unlock-remote.sh` from their workstation. No cloud secret manager used; see `08_SECRETS_MANAGEMENT.md`.
- Spawn controller: calls DO API to create/destroy ephemeral worker droplets
- Kill-switch: Ctrl+C on Box2 triggers `destroy_all_ephemeral_droplets()`

**Box3 — Intelligence + Observability (personal account ✅ — permanent)**
- **PERMANENT**: Personal email, always-free tier, no expiry risk.
- PostgreSQL streaming replica from **Box2** (HA + read offload)
- CertStream daemon (passive cert log monitoring via `CERTSTREAM_KEYWORDS`)
- NVD CVE monitor (polls NVD API, passive)
- `mcp_stats` analytics consumer
- Loki + Grafana + Tempo self-hosted (observability stack receiving traces via `OTEL_ENDPOINT` from Box1/Box2)
- NATS secondary node (control plane resilience)
- **Droplet janitor cron**: lists DO droplets every 15min via API, force-destroys any tagged `purpose=redteam-ephemeral` exceeding `TTL=6h`

**Box4 — Interactsh OOB Server (Azure Africa VPS ✅ — persistent)**
- **PERSISTENT**: Azure Student VPS, personal account. Not tied to Oracle AUP. Stable public IP + DNS authority.
- `interactsh-server` listening on ports 53 (DNS), 80 (HTTP), 443 (HTTPS), 25 (SMTP)
- DNS authority over `*.oast.<your-domain>` via NS glue record
- REST API on `:1337` (Tailscale-only) polled by Box2 to correlate callbacks to scan findings
- Captures blind SSRF, blind XSS, blind command injection, DNS rebinding, SMTP header injection
- Joined to same Tailscale mesh as Box1/2/3; API never exposed to public internet

### 3.2 Data Plane (DigitalOcean ephemeral — touches targets)

- Droplet size: `s-1vcpu-1gb` ($0.009/hr ≈ $6/mo if 24/7, prorated per use)
- Image: snapshot pre-baked with worker binary + dependencies (nmap, masscan, etc.)
- Bootstrap: cloud-init pulls pre-compiled `redteam_rust_core` ARM/x86_64 binary from **Box1** Object Storage (signed URL), joins Tailscale via ephemeral auth-key
- Execution: `redteam_rust_core --worker --postgres-url postgres://box2.tailscale-ip:5432/... --node-id do-${droplet_id}`
- OOB payloads: worker uses `INTERACTSH_SERVER_URL` + `INTERACTSH_TOKEN` (from `secrets.env`) to generate unique payload subdomains pointing to Box4
- Lifecycle: pulls one or more jobs from `scan_queue`, executes scan plugins (including OOB probes), pushes findings via Postgres connection to **Box2**, then exits
- TTL enforcement: `at +6h shutdown -h now` in cloud-init prevents orphan billing
- Memory bound: `config.soft_memory_limit_mb = 600` (reserves 400MB for OS + nmap)

## 4. Cross-Tenancy Networking

3 Oracle boxes live in 3 different tenancies. No native VCN peering between tenancies without paid Remote Peering Connection. Solution: **Tailscale mesh** over public internet.

- Each Oracle box runs Tailscale daemon, joined to single tailnet
- DO ephemeral droplets join same tailnet via ephemeral auth-keys (`tailscale up --ephemeral --advertise-tags=tag:redteam-worker`)
- All control-plane services bind to `tailscale0` interface only — Postgres, NATS, dashboard never exposed on public IP
- ACL example:
  ```jsonc
  {
    "tagOwners": { "tag:redteam-worker": ["autogroup:admin"] },
    "acls": [
      { "action": "accept", "src": ["tag:redteam-worker"], "dst": ["100.x.x.x:5432", "100.x.x.x:4222"] },
      { "action": "accept", "src": ["autogroup:admin"], "dst": ["*:*"] }
    ]
  }
  ```
- Tailscale free tier (100 devices) sufficient for 3 control boxes + ephemeral worker pool

## 5. DO Droplet Lifecycle

### Spawn (**Box2** initiates)
1. **Box2** reads `DO_TOKEN` from `/run/mimikri/secrets.env` (populated by operator unlock — `08_SECRETS_MANAGEMENT.md` §4.3)
2. Calls DO API `POST /v2/droplets` with image=snapshot, region matching target geography, user-data containing cloud-init script
3. Cloud-init script:
   - Installs Tailscale, joins tailnet with one-shot auth key
   - Downloads worker binary from **Box1** Object Storage (signed URL, 1h TTL; if Box1 offline, fallback to Box2 local cache)
   - Sets `at +6h shutdown -h now`
   - Starts `redteam_rust_core --worker --postgres-url postgres://box2-tailscale-ip:5432/...`
4. Droplet tagged `purpose=redteam-ephemeral`, `spawned-by=box2`, `campaign=<scope_id>`

### Execution
- Worker polls `scan_queue` on **Box2** Postgres via Tailscale-tunneled connection
- Claims job (`UPDATE ... SET claimed_by = 'do-${droplet_id}'`)
- Executes scan plugins (active probes leave DO IP, target sees only DO)
- Pushes findings rows to **Box2** Postgres + emits NATS events for swarm coordination

### Destroy
- **Normal**: worker exits cleanly after job pool drained → cloud-init shutdown timer or explicit `poweroff` → **Box2** detects droplet stopped, calls DO API `DELETE /v2/droplets/{id}`
- **Forced**: Box3 janitor cron detects droplet > TTL → DO API destroy
- **Kill-switch**: Ctrl+C on **Box2** triggers `infrastructure/digital_ocean.rs` cleanup → enumerate all droplets tagged `purpose=redteam-ephemeral` for current campaign, destroy in parallel

## 6. Traffic Patterns and OPSEC Visibility

### What Oracle sees (per-tenancy outbound)
- HTTPS to `api.digitalocean.com` (droplet spawn/destroy)
- Tailscale UDP to `derp.tailscale.com` and direct peer connections
- HTTPS to `api.hackerone.com`, `services.nvd.nist.gov`, Discord webhooks, GitHub
- Postgres replication traffic **Box2↔Box3** over Tailscale
- Box2 polls Box4 (Azure) API via Tailscale: `GET https://box4-tailscale-ip:1337/poll`
- **Zero packets to target IPs** — passes Oracle abuse heuristics

### What DigitalOcean sees
- Inbound Tailscale connection + Postgres query traffic from Oracle
- Outbound scan probes to authorized targets (within DO TOS for authorized pentests)
- HTTPS pull of worker binary at droplet boot

### What targets see
- Only DO ephemeral IPs (rotating every campaign)
- No attribution path to Oracle control plane (encrypted tunnel)

## 7. Cost Model — Student Credit Only (Zero Out-of-Pocket Target)

**Hard constraint**: This deployment runs entirely on student promotional credits with no personal payment method attached. Total budget is **fixed and non-renewable**.

### Credit inventory

| Provider | Source | Amount | Validity | Renewable |
|---|---|---|---|---|
| Oracle Cloud (Box1) | Oracle Academy Student ⚠️ | $300 USD | 365 days | No |
| Oracle Cloud (Box2) | Personal signup ✅ | $0 (always-free only) | Permanent | N/A |
| Oracle Cloud (Box3) | Personal signup ✅ | $0 (always-free only) | Permanent | N/A |
| DigitalOcean | GitHub Student Pack | $200 USD | 365 days from activation | No |
| **Total** | | **$500 USD / year** | | |

### Oracle always-free baseline (zero cost, permanent, per tenancy)
- 4 ARM Ampere cores + 24GB RAM (Box1 + Box2 + Box3 = 12c / 72GB total)
- 200GB block storage per tenancy (600GB total)
- 10TB outbound egress per tenancy (30TB total)
- 20GB Object Storage Standard per tenancy (60GB total free)
- 2× Autonomous Database 20GB per tenancy (6 instances total — usable as Postgres-replica alternative)
- Bastion service within usage caps
- Load Balancer 10Mbps

### Oracle $300 credit — ACTIVE-SPEND allocation (no card on file)

**Critical fact:** the $300 credit was granted via Oracle for Education / Oracle Academy linkage of the operator's university email. **No payment method is registered on the account.** This means Oracle structurally cannot auto-bill at credit exhaustion — paid services simply suspend pending an explicit "upgrade to paid" action that the operator never has to take.

Strategy: actively spend the $300 during the 365-day credit window on services that maximize Mimikri security and operational maturity. At day 350, run the graduation gate (`09_INCIDENT_RESPONSE.md`) to migrate data off paid tiers. At day 366, paid services auto-suspend; Always-Free continues indefinitely.

| Service | Annual allocation | What it buys | Graduation behavior at day 365 |
|---|---|---|---|
| OCI Object Storage 250GB | $80 | Forensic findings archive + worker binary versioned distribution + AIDE baselines; hosted on Box1 student tenancy | Auto-suspend. Operator prunes data to ≤60GB free (20GB × 3 tenancies) before day 350. |
| OCI Block Volume Backup | $60 | Oracle-managed daily snapshots of **Box2** boot + Postgres data volumes via Tailscale snapshot script — protects the actual coordinator | Last weekly pg_dump exported to operator local NAS before day 360. |
| OCI Vulnerability Scanning Service (VSS) | $40 | Continuous CIS/CVE scan of the 3 control-plane boxes themselves; complements AIDE+auditd by catching host-level vulnerabilities | Scanning stops at expiry; AIDE + unattended-upgrades remain primary. |
| OCI Logging Analytics | $40 | Centralized log retention 90d with parsing rules — independent retention path if Box3 (Loki host) is compromised | Parsing rules migrated to Loki before expiry; raw logs accessible during suspend. |
| OCI Bastion overflow | $20 | Buffer above free-tier session cap for incident-response months | Falls back to free-tier cap. |
| Egress overage buffer | $40 | Cushion for high-scan months exceeding 10TB/mo Box1 cap | Throttle concurrency below cap. |
| Reserve / Unforeseen | $20 | One-off unplanned spend | Untouched if not needed. |
| **Active total** | **$300** | Average ~$25/month over 12 months | Auto-suspend at credit expiry (no billing event) |

Services explicitly NOT spent on (and why):
- **WAF** — Cloudflare Free covers managed rules + rate limit + Zero Trust Access. Redundant.
- **Network Firewall** — UFW + Tailscale ACL cover the threat model.
- **API Gateway** — single-operator dashboard traffic is low-volume.
- **OCI Streaming (Kafka)** — NATS already covers messaging.
- **Compute expansion** — 12c/72GB always-free across 3 boxes is enough; paid compute would disappear at day 365 (creates dependency).
- **OCI Container Registry** — Object Storage signed URLs already cover worker binary distribution.

### DigitalOcean $200 burn plan (365 days)

Pure ephemeral droplet usage — every dollar buys scan-hours.

| Droplet plan | Cost/hr | Cost/4h campaign | Campaigns from $200 |
|---|---|---|---|
| `s-1vcpu-512mb` | $0.006 | $0.024 | ~8,333 campaigns |
| `s-1vcpu-1gb` (recommended) | $0.009 | $0.036 | ~5,555 campaigns |
| `s-1vcpu-2gb` | $0.018 | $0.072 | ~2,777 campaigns |
| `s-2vcpu-2gb` | $0.027 | $0.108 | ~1,851 campaigns |

**Realistic burn at 50 campaigns/month × 5 droplets × 4h**:
- 50 × 5 × 4h × $0.009 = $9/mo → $108/yr → $92 remaining in DO buffer

**Strategy: aim < $15/mo DO spend** to keep buffer for surge campaigns (e.g., large CTF event burst, sustained recon).

### Combined ceiling
- **Oracle**: ~$300/yr ceiling, hard-capped at credit exhaustion (no auto-charge)
- **DigitalOcean**: ~$200/yr ceiling, hard-capped at credit exhaustion (account suspends paid resources, requires manual upgrade)
- **Out-of-pocket target**: **$0** for first 365 days

### Post-credit-exhaustion cost (worst case if you want to keep running)
- Oracle always-free: $0 indefinitely (Box1/Box2/Box3 12c/72GB survives)
- DO ephemeral fallback: ~$10-15/mo if you add personal payment, OR move data plane to free alternatives (see Section 13)

### Egress accounting
- Oracle → DO outbound: < 1MB per droplet spawn (negligible vs 10TB/mo Box1 quota)
- DO → Oracle inbound findings: counts as inbound to Oracle (FREE, no quota)
- Scan traffic (DO → target): consumed from DO droplet bandwidth (1TB/mo per droplet, far above need)

## 8. Failure and Degradation Modes

### Box4 down (OOB server offline)
- **Degraded but tolerable.** Active scans continue.
- Blind SSRF / blind XSS / blind injection findings will not be confirmed (payloads fire but callbacks are not captured)
- Workers continue running all non-OOB plugins (port scans, service enum, CVE matching) without interruption
- No data loss in Postgres; findings that didn't trigger OOB still get recorded
- **Recovery**: restart `interactsh` service on Box4. No data migration needed.
- **If Box4 is permanently down**: use `projectdiscovery.io` hosted interactsh or migrate to a DO Reserved IP

### Box1 down (student tenancy suspended / email revoked)
- **Expected and tolerated.** Box1 is sacrificable by design.
- AI enrichment (Ollama, router.rs, compressor.rs, BloodHound) goes offline — findings accumulate in Box2 Postgres without LLM classification
- Worker binary distribution from Object Storage fails → fallback: Box2 serves binary from local cache (`/opt/mimikri/bin/worker-cache/`)
- OCI paid services (Object Storage cold archive, VSS scanning, Logging Analytics) suspend → Loki on Box3 becomes sole log store; AIDE primary defence
- **Coordinator (Box2), Postgres primary (Box2), NATS hub (Box2), Dashboard (Box2), data plane workers, Box3 replica — ALL continue unaffected**
- Recovery: enrich backlog manually or restore Box1 from snapshot if account reinstated

### Box2 down (coordinator offline — high impact)
- Workers lose Postgres connection; they finish in-progress jobs and self-destroy via TTL timer
- No new droplets can be spawned (Box2 holds DO_TOKEN)
- Box3 replica promotes to primary (`pg_ctl promote`) to preserve findings already written
- Box1 enrichment pauses (no queue to drain from Box2)
- **Recovery**: restore Box2 from snapshot (< 4h), re-unlock secrets, redirect Box3 replica back to streaming from Box2

### Box3 down (intel/observability offline)
- Control plane and scans continue
- Lost: passive intel ingest (CertStream, NVD), observability (Loki, Grafana), droplet janitor cron, Postgres replica
- **Risk**: orphan droplets if Box2 also misses cleanup → mitigate with cloud-init TTL `at +6h shutdown` (independent of janitor)

### DO API outage
- No new droplets spawn, scan queue accumulates on Box2
- Existing droplets finish current jobs and self-destroy via TTL
- Control plane unaffected

### $300 credit exhausted (day 365) — Box1 student credit only
- Day 350 graduation gate has already migrated paid-tier data to Always-Free tiers + operator local NAS (see `09_INCIDENT_RESPONSE.md` SEV-3 Credit Exhaustion procedure).
- Oracle auto-suspends paid services on Box1 tenancy (Object Storage > 20GB, Block Volume Backup, VSS, Logging Analytics, Bastion overflow). No billing event — no card on file.
- Secrets remain under `age` + YubiKey (on Box2, independent of Box1).
- Loki on Box3 becomes sole authoritative log store; AIDE + unattended-upgrades cover what VSS used to.
- **Box2 and Box3 (personal accounts, always-free) survive indefinitely. 12-core 72GB control plane continues unaffected.**

## 9. $300 Credit Allocation Strategy — ACTIVE SPEND

Detailed allocation in §7 above. Summary view:

| Bucket | Monthly target | Annual cap | Day-350 graduation step |
|---|---|---|---|
| Object Storage | ~$7 | $80 | Prune > 60GB total across 3 tenancies |
| Block Volume Backup | ~$5 | $60 | Export last weekly snapshot to local NAS |
| Vulnerability Scanning Service | ~$3 | $40 | Export 12-month findings, disable target |
| Logging Analytics | ~$3 | $40 | Migrate parsing rules to Loki, export raw logs |
| Bastion overflow | ~$2 | $20 | Drop to free-tier cap |
| Egress overage | as-needed | $40 | Throttle if approaching cap |
| Reserve | as-needed | $20 | Untouched if unused |
| **Total active monthly** | **~$25** | **$300/yr** | All migrated by day 360 |

After day 365: paid services auto-suspend (no billing — no card). Always-Free tier continues. Graduation procedure in `09_INCIDENT_RESPONSE.md` "Credit Exhaustion (day 350)".

## 10. TOS Compliance Notes

### Oracle Cloud Infrastructure
- Active scanning from Oracle infrastructure: **prohibited** (TOS §4.2 Acceptable Use)
- Topology compliance: control plane services are passive (queue management, AI inference, observability, intel aggregation). No outbound TCP/UDP probes to non-Oracle infrastructure beyond standard API HTTPS calls. Compliant.
- Egress sustained > 10TB/mo per account: Oracle may classify as "non-personal use" and suspend free tier. Mitigation: keep Box1 < 8TB/mo, distribute load to Box2/Box3 if needed.

### DigitalOcean
- Authorized penetration testing: permitted with prior notification to `abuse@digitalocean.com` for sustained campaigns
- For bug bounty / CTF / HackerOne scope: typically no notification required, but document scope in `policy.json` and `--scope-id` for auditability
- Ephemeral droplet pattern: aligns with DO documented use cases, not flagged as abusive

### Target legal compliance
- `policy.json` declares `in_scope` and `out_of_scope` patterns
- `--scope-id` enforces V15.1 scope isolation
- HackerOne sync via `SCOPE_SYNC=true` + `H1_API_KEY` auto-fetches authorized scope
- Reactive chain depth ≤ 5 (`core.reactive_depth`) prevents unauthorized lateral expansion
- Destructive probe dual-gate (`REDTEAM_DESTRUCTIVE=1` + config flag) enforced regardless of substrate

## 11. Implementation Status

This document describes the **target architecture**. Current state:

| Component | Status |
|---|---|
| `infrastructure/digital_ocean.rs` ephemeral spawn | Implemented (V14.1) |
| Kill-switch on Ctrl+C | Implemented (V14.1) — **must point to Box2** |
| Worker mode `--worker` | Implemented |
| PostgreSQL `scan_queue` table | Documented in CLAUDE.md, requires migration — **on Box2** |
| Tailscale cross-tenancy mesh | **Not yet implemented** — manual setup required |
| Box1(AI)/Box2(coord)/Box3(intel) role separation | **Not yet deployed** — current dev runs monolithic |
| Cloud-init worker bootstrap script | **Not yet written** — must point to Box2 Postgres |
| Droplet janitor cron (Box3) | **Not yet written** |
| `age` + YubiKey secrets workflow | **Documented in `08_SECRETS_MANAGEMENT.md`** — secrets unlock on **Box2** |
| Object Storage findings archive sink (Box1) | **Not yet implemented** — extend `core/sink/` (new backend module) |
| Box2→Box3 Postgres streaming replication | **Not yet configured** (was Box1→Box3, now Box2→Box3) |
| Box1 binary distribution cache fallback on Box2 | **Not yet implemented** |

Implementation order proposed (post Sprint 7.5 closure):
1. Sprint 8.A: Tailscale provisioning scripts + ACL templates
2. Sprint 8.B: Cloud-init template + worker binary distribution (Box1 Object Storage primary, Box2 cache fallback)
3. Sprint 8.C: ~~OCI Vault integration~~ — **DROPPED**, replaced by `age` + YubiKey workflow documented in `08_SECRETS_MANAGEMENT.md`. No code changes required.
4. Sprint 8.D: Droplet janitor cron + monitoring
5. Sprint 8.E: Postgres replication **Box2→Box3** (coordinator is Box2)
6. Sprint 8.F: Object Storage findings sink on Box1
7. Sprint 8.G: End-to-end smoke test (1 campaign, 1 droplet, full lifecycle)

## 12. References

- `infrastructure/digital_ocean.rs` — DO API client, kill-switch
- `core/engine/app.rs` — `RedTeamEngine` initialization
- `utils/config.rs` — Env loading (reads `/run/mimikri/secrets.env` via systemd `EnvironmentFile`)
- `core/sink/mod.rs` — `DataSink` trait (target for Object Storage backend)
- `stealth_opsec.md` — Stealth infrastructure principles
- `multi_vps_deployment.original.md` — Prior multi-VPS thinking
- DigitalOcean Acceptable Use Policy: https://www.digitalocean.com/legal/acceptable-use-policy
- Oracle Cloud Acceptable Use Policy: https://www.oracle.com/legal/cloud-services.html
