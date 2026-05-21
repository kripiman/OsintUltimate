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
┌────────────────────────────────────────────────────────────────────────┐
│                        CONTROL PLANE (Oracle)                          │
│                                                                        │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐    │
│  │  Box1 (student)  │  │  Box2 (acct B)   │  │  Box3 (acct C)   │    │
│  │  4c/24GB ARM     │  │  4c/24GB ARM     │  │  4c/24GB ARM     │    │
│  │                  │  │                  │  │                  │    │
│  │ • Coordinator    │  │ • AI/LLM router  │  │ • Postgres replica│   │
│  │ • Dashboard 8080 │  │ • compressor.rs  │  │ • CertStream     │    │
│  │ • Postgres queue │  │ • OllamaClient   │  │ • NVD monitor    │    │
│  │ • NATS hub       │  │ • Findings enrich│  │ • Loki/Grafana   │    │
│  │ • Sink aggregator│  │ • BloodHound     │  │ • OTEL collector │    │
│  │ • secrets.env.age│  │ • Bug bounty     │  │ • NATS secondary │    │
│  │   (age/YubiKey)  │  │   auto-submit    │  │ • Droplet janitor│    │
│  └────────┬─────────┘  └────────┬─────────┘  └────────┬─────────┘    │
│           │                     │                     │              │
│           └─────── Tailscale mesh (100.x.x.x) ────────┘              │
│                              │                                       │
└──────────────────────────────┼───────────────────────────────────────┘
                               │
                  ┌────────────┴────────────┐
                  │  DO API (spawn/destroy) │
                  │  Tailscale auth-key     │
                  └────────────┬────────────┘
                               │
┌──────────────────────────────┼───────────────────────────────────────┐
│                       DATA PLANE (DigitalOcean ephemeral)            │
│                                                                      │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐   │
│  │ Droplet  │ │ Droplet  │ │ Droplet  │ │ Droplet  │ │ Droplet  │   │
│  │ 1c/1GB   │ │ 1c/1GB   │ │ 1c/1GB   │ │ 1c/1GB   │ │ 1c/1GB   │   │
│  │ --worker │ │ --worker │ │ --worker │ │ --worker │ │ --worker │   │
│  │ TTL=6h   │ │ TTL=6h   │ │ TTL=6h   │ │ TTL=6h   │ │ TTL=6h   │   │
│  └─────┬────┘ └─────┬────┘ └─────┬────┘ └─────┬────┘ └─────┬────┘   │
│        │            │            │            │            │        │
└────────┼────────────┼────────────┼────────────┼────────────┼────────┘
         │            │            │            │            │
         ▼            ▼            ▼            ▼            ▼
                          [ AUTHORIZED TARGETS ]
                  (nmap, scanning/*, exploitation/*)
```

## 3. Plane Responsibilities

### 3.1 Control Plane (Oracle — never touches targets)

**Box1 — Coordinator (student account, $300 credit)**
- `RedTeamEngine` orchestrator (no scanning plugins enabled)
- PostgreSQL primary (queue table `scan_queue`, findings table, `mcp_stats`)
- Dashboard HTTP server on `:8080` (Tailscale-bound only, no public IP)
- NATS hub for swarm V4.0 inter-agent messaging
- Sink aggregator: receives findings from data plane workers, dispatches to JSONL/webhooks/Discord
- Secrets: `secrets.env.age` encrypted to operator's YubiKey-bound `age` identity. Decrypted into tmpfs at `/run/mimikri/secrets.env` only when the operator runs `unlock-remote.sh` from their workstation. No cloud secret manager used; see `08_SECRETS_MANAGEMENT.md`.
- OCI Object Storage: archives baselines (`golden_baseline.json`), findings cold storage, pre-built worker binaries

**Box2 — AI Enrichment Pipeline (free tier)**
- `router.rs` classification stage (passive — operates on already-collected findings)
- `compressor.rs` (`compress_finding_dense`, `compress_swarm_context`, `compress_target_lean`)
- Local LLM via OllamaClient (CPU inference on ARM, no GPU required)
- BloodHound graph post-processing (AdIngestor + `bloodhound.rs`)
- Bug bounty auto-submit sink (HackerOne API calls — outbound to API only, not to targets)
- Findings deduplication and correlation

**Box3 — Intelligence + Observability (free tier)**
- PostgreSQL streaming replica from Box1 (HA + read offload)
- CertStream daemon (passive cert log monitoring via `CERTSTREAM_KEYWORDS`)
- NVD CVE monitor (polls NVD API, passive)
- `mcp_stats` analytics consumer
- Loki + Grafana + Tempo self-hosted (observability stack receiving traces via `OTEL_ENDPOINT` from Box1/Box2)
- NATS secondary node (control plane resilience)
- **Droplet janitor cron**: lists DO droplets every 15min via API, force-destroys any tagged `purpose=redteam-ephemeral` exceeding `TTL=6h`

### 3.2 Data Plane (DigitalOcean ephemeral — touches targets)

- Droplet size: `s-1vcpu-1gb` ($0.009/hr ≈ $6/mo if 24/7, prorated per use)
- Image: snapshot pre-baked with worker binary + dependencies (nmap, masscan, etc.)
- Bootstrap: cloud-init pulls pre-compiled `redteam_rust_core` ARM/x86_64 binary from Box1 Object Storage, joins Tailscale via ephemeral auth-key
- Execution: `redteam_rust_core --worker --postgres-url postgres://box1.tailscale-ip:5432/... --node-id do-${droplet_id}`
- Lifecycle: pulls one or more jobs from `scan_queue`, executes scan plugins, pushes findings via Postgres connection, then exits
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

### Spawn (Box1 initiates)
1. Box1 reads `DO_TOKEN` from `/run/mimikri/secrets.env` (populated by operator unlock — `08_SECRETS_MANAGEMENT.md` §4.3)
2. Calls DO API `POST /v2/droplets` with image=snapshot, region matching target geography, user-data containing cloud-init script
3. Cloud-init script:
   - Installs Tailscale, joins tailnet with one-shot auth key
   - Downloads worker binary from Object Storage (signed URL, 1h TTL)
   - Sets `at +6h shutdown -h now`
   - Starts `redteam_rust_core --worker ...`
4. Droplet tagged `purpose=redteam-ephemeral`, `spawned-by=box1`, `campaign=<scope_id>`

### Execution
- Worker polls `scan_queue` via Tailscale-tunneled Postgres
- Claims job (`UPDATE ... SET claimed_by = 'do-${droplet_id}'`)
- Executes scan plugins (active probes leave DO IP, target sees only DO)
- Pushes findings rows to Postgres + emits NATS events for swarm coordination

### Destroy
- **Normal**: worker exits cleanly after job pool drained → cloud-init shutdown timer or explicit `poweroff` → Box1 detects droplet stopped, calls DO API `DELETE /v2/droplets/{id}`
- **Forced**: Box3 janitor cron detects droplet > TTL → DO API destroy
- **Kill-switch**: Ctrl+C on Box1 triggers `infrastructure/digital_ocean.rs` cleanup → enumerate all droplets tagged `purpose=redteam-ephemeral` for current campaign, destroy in parallel

## 6. Traffic Patterns and OPSEC Visibility

### What Oracle sees (per-tenancy outbound)
- HTTPS to `api.digitalocean.com` (droplet spawn/destroy)
- Tailscale UDP to `derp.tailscale.com` and direct peer connections
- HTTPS to `api.hackerone.com`, `services.nvd.nist.gov`, Discord webhooks, GitHub
- Postgres replication traffic Box1↔Box3 over Tailscale
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
| Oracle Cloud (Box1 only) | Oracle Academy Student | $300 USD | 365 days | No |
| Oracle Cloud (Box2) | Standard signup | $0 (always-free only) | Permanent | N/A |
| Oracle Cloud (Box3) | Standard signup | $0 (always-free only) | Permanent | N/A |
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
| OCI Object Storage 250GB | $80 | Forensic archive + worker binary versioned distribution + AIDE baselines + Postgres weekly age-encrypted snapshots | Auto-suspend. Operator prunes data to ≤60GB free (20GB × 3 tenancies) before day 350. |
| OCI Block Volume Backup | $60 | Oracle-managed daily snapshots of Box1 boot + Postgres data volumes (immutable, off-host) — survives ransomware on Box1 disk | Last weekly snapshot exported to operator local NAS before day 360. |
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

### Box1 down (control plane partial loss)
- Box3 replica promotes to primary (`pg_ctl promote`)
- Box2 enrichment pauses (no queue to drain)
- Existing droplets continue executing claimed jobs, push findings to Box3 promoted Postgres
- Box3 janitor still destroys droplets at TTL
- **No active scans lost**, no orphan billing

### Box2 down (AI offline)
- Coordinator unaffected, workers unaffected
- Findings accumulate in Postgres without LLM classification
- Enrichment backlog processed when Box2 returns

### Box3 down (intel/observability offline)
- Control plane and scans continue
- Lost: passive intel ingest, observability, droplet janitor cron
- **Risk**: orphan droplets if Box1 also misses cleanup → mitigate with cloud-init TTL `at +6h shutdown` (independent of janitor)

### DO API outage
- No new droplets spawn, scan queue accumulates
- Existing droplets finish current jobs and self-destroy via TTL
- Control plane unaffected

### $300 credit exhausted (day 365)
- Day 350 graduation gate has already migrated paid-tier data to Always-Free tiers + operator local NAS (see `09_INCIDENT_RESPONSE.md` SEV-3 Credit Exhaustion procedure).
- Oracle auto-suspends paid services (Object Storage > 20GB, Block Volume Backup, VSS, Logging Analytics, Bastion overflow). No billing event because no card is on file.
- Secrets remain under `age` + YubiKey (independent of any Oracle service).
- Loki on Box3 becomes sole authoritative log store; AIDE + unattended-upgrades cover what VSS used to.
- **12-core 72GB control plane survives indefinitely on Always-Free tier alone.**

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
| Kill-switch on Ctrl+C | Implemented (V14.1) |
| Worker mode `--worker` | Implemented |
| PostgreSQL `scan_queue` table | Documented in CLAUDE.md, requires migration |
| Tailscale cross-tenancy mesh | **Not yet implemented** — manual setup required |
| Box1/Box2/Box3 role separation | **Not yet deployed** — current dev runs monolithic |
| Cloud-init worker bootstrap script | **Not yet written** |
| Droplet janitor cron (Box3) | **Not yet written** |
| `age` + YubiKey secrets workflow | **Documented in `08_SECRETS_MANAGEMENT.md`** — no code-side changes required; `utils/config.rs` continues to read env vars supplied by tmpfs `/run/mimikri/secrets.env` |
| Object Storage findings archive sink | **Not yet implemented** — extend `core/sink.rs` |
| Box1→Box3 Postgres streaming replication | **Not yet configured** |

Implementation order proposed (post Sprint 7.5 closure):
1. Sprint 8.A: Tailscale provisioning scripts + ACL templates
2. Sprint 8.B: Cloud-init template + worker binary distribution via Object Storage
3. Sprint 8.C: ~~OCI Vault integration~~ — **DROPPED**, replaced by `age` + YubiKey workflow documented in `08_SECRETS_MANAGEMENT.md`. No code changes required.
4. Sprint 8.D: Droplet janitor cron + monitoring
5. Sprint 8.E: Postgres replication Box1→Box3
6. Sprint 8.F: Object Storage findings sink
7. Sprint 8.G: End-to-end smoke test (1 campaign, 1 droplet, full lifecycle)

## 12. References

- `infrastructure/digital_ocean.rs` — DO API client, kill-switch
- `core/engine.rs` — `RedTeamEngine` initialization
- `utils/config.rs` — Env loading (reads `/run/mimikri/secrets.env` via systemd `EnvironmentFile`)
- `core/sink.rs` — `DataSink` trait (target for Object Storage backend)
- `stealth_opsec.md` — Stealth infrastructure principles
- `multi_vps_deployment.original.md` — Prior multi-VPS thinking
- DigitalOcean Acceptable Use Policy: https://www.digitalocean.com/legal/acceptable-use-policy
- Oracle Cloud Acceptable Use Policy: https://www.oracle.com/legal/cloud-services.html
