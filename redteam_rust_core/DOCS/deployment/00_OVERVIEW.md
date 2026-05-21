# Deployment Runbook — Overview & Threat Model

**Status**: Operational runbook
**Scope**: 3× Oracle Cloud ARM boxes (control plane) + DigitalOcean ephemeral droplets (data plane)
**Audience**: Operator deploying Mimikri RedTeam Core for authorized bug bounty / pentest engagements
**Last reviewed**: 2026-05-20

---

## 1. Index

| # | File | Purpose |
|---|---|---|
| 01 | `01_BASE_HARDENING.md` | OS hardening applied to all 3 Oracle boxes |
| 02 | `02_BOX1_AI_ENRICHMENT.md` | Box1: Ollama LLM, AI router, BloodHound, bug bounty submit (student ⚠️ — sacrificable) |
| 03 | `03_BOX2_COORDINATOR.md` | Box2: Postgres primary, dashboard, NATS hub, sink aggregator (personal ✅ — permanent) |
| 04 | `04_BOX3_INTEL_OBSERVABILITY.md` | Box3: Postgres replica, CertStream, NVD, Loki/Grafana, droplet janitor |
| 05 | `05_BOX4_INTERACTSH.md` | Box4: interactsh OOB server (Azure Africa VPS — Azure Student, permanent) |
| 06 | `06_DO_EPHEMERAL_WORKERS.md` | DigitalOcean droplet lifecycle + cloud-init |
| 07 | `07_DASHBOARD_PUBLIC_ACCESS.md` | Cloudflare Tunnel for `mimikri.<tld>` |
| 08 | `08_SECRETS_MANAGEMENT.md` | `age` + YubiKey + tmpfs (zero-cost, hardware-bound) |
| 09 | `09_INCIDENT_RESPONSE.md` | Kill-switch, IR playbooks, forensic capture |
| 10 | `10_SMOKE_TEST.md` | End-to-end validation: 1 campaign → 1 droplet → findings + OOB |

Read in order on first deploy. After deployment, use as task-specific reference.

---

## 2. Threat Model

### 2.1 Assets

| Asset | Sensitivity | Location |
|---|---|---|
| Postgres findings DB | High — contains target vulnerabilities | **Box2** (primary), Box3 (replica) |
| API keys (Shodan, FOFA, NVD, etc.) | High — paid credentials | `secrets.env.age` on **Box2** → tmpfs `/run/mimikri/secrets.env` |
| `DO_TOKEN` (DigitalOcean) | Critical — spawns billable infra | `secrets.env.age` on **Box2** only; decryption requires operator YubiKey |
| `H1_API_KEY` (HackerOne) | High — can submit reports | `secrets.env.age` on **Box2** only |
| `INTERACTSH_TOKEN` | Critical — authenticates OOB poll | `secrets.env` on **Box2** + Box4 + DO workers | 90d |
| `INTERACTSH_URL` | Medium | Box2 (polling) + workers (payload gen) | static |
| Worker binary | Medium — pre-compiled scanner | Box1 Object Storage (cold) + Box2 local cache (fallback) |
| Scan logs / findings JSONL | Medium — discloses targets in scope | **Box2** disk (primary), Box3 archive |

### 2.2 Adversaries

| Adversary | Capability | Mitigation |
|---|---|---|
| Cloud provider abuse heuristics (Oracle TOS) | Account termination if active scans detected | Control plane never originates probes to targets (only DO does) |
| Bug bounty target SOC | Block IPs, file abuse reports | Ephemeral DO IPs, rotate per campaign |
| Opportunistic internet scanners | Mass scan public IPs of boxes | Tailscale-only binds, no public exposed services except dashboard via Cloudflare Tunnel |
| Compromised dev workstation | Steal SSH keys, .env files | Hardware MFA on SSH, age-encrypted .env, no plaintext secrets at rest |
| Insider / shared account | Misuse of credentials | Single-operator deployment, all actions audit-logged via auditd |
| Supply chain (Rust deps, Ollama model) | Malicious code in dependencies | `cargo audit` in CI, pinned `Cargo.lock`, model hashes verified |

### 2.3 Out of scope

- Nation-state APT targeting infrastructure (deploy is not designed to resist)
- Physical attacks on cloud datacenters
- Side-channel attacks against shared cloud hardware

---

## 3. Prerequisites

### 3.1 Accounts required

| Service | Tier | Notes |
|---|---|---|
| Oracle Cloud × 3 tenancies | 1× student ($300 credit) ⚠️, 2× personal always-free ✅ | Box1 student credit = sacrificable (may expire with university email); Box2/Box3 personal = permanent |
| Azure Student VPS × 1 | Azure Student credit | Box4: interactsh OOB server. 1GB RAM, 2 vCPU, Africa region. Permanent while credit lasts; migrate to DO Reserved IP if expired |
| DigitalOcean | GitHub Student Pack ($200) | Activate via education.github.com |
| Cloudflare | Free | For tunnel + DNS |
| Tailscale | Free (100 devices) | Single tailnet across all boxes |
| GitHub | Free | Private repo for `age`-encrypted secrets, optional |
| Domain registrar | Student promo ("mimikri") | DNS managed by Cloudflare |
| Bug bounty platform | HackerOne / Bugcrowd | API key per platform |

### 3.2 Local tooling

```bash
# Mandatory
cargo --version              # >= 1.83 for redteam_rust_core build
rustc --version              # stable
git --version
ssh --version                # OpenSSH 9+
gpg --version                # for signed commits
age --version                # secret encryption (https://age-encryption.org)
tailscale --version          # CLI for ACL push
doctl --version              # DigitalOcean CLI
age-plugin-yubikey --version # YubiKey-backed age identity (MANDATORY)
yubikey-manager              # YubiKey provisioning (MANDATORY)

# Recommended
oci --version                # Oracle Cloud CLI — only for monitoring/billing checks (no longer needed for secrets)
sops --version               # if you prefer SOPS over age
trivy --version              # scan worker container/binary
```

### 3.3 Hardware MFA (strongly recommended)

A YubiKey 5 (or Solo Key) for:
- SSH login to all 3 boxes (`PubkeyAuthentication yes` + `~/.ssh/authorized_keys` with `sk-ssh-ed25519@openssh.com`)
- GPG-signed commits
- 2FA on Oracle / DigitalOcean / Cloudflare / GitHub / Tailscale consoles

Soft TOTP (Authy/Aegis) acceptable as fallback but reduces resistance to phishing.

---

## 4. Deployment Order

Strict sequence. Do not skip — each step assumes prior steps completed.

```
Phase 1 — Foundation (Day 1-2)
  ├─ Sign up 3 Oracle tenancies, 1 DO, 1 Cloudflare
  ├─ Provision 3 ARM VM.Standard.A1.Flex (4c/24GB) on each Oracle tenancy
  ├─ DNS: point mimikri.<tld> to Cloudflare nameservers
  └─ Generate hardware-backed SSH keys (YubiKey)

Phase 2 — Hardening (Day 2-3)
  └─ 01_BASE_HARDENING.md on all 3 boxes

Phase 3 — Mesh (Day 3)
  └─ 05_TAILSCALE_MESH.md — connect all boxes + DO droplet template

Phase 4 — Secrets (Day 3)
  └─ 08_SECRETS_MANAGEMENT.md — `age` + YubiKey + tmpfs (zero-cost)

Phase 5 — Roles (Day 4-6)
  ├─ 03_BOX2_COORDINATOR.md     (personal account ✅ — deploy first)
  ├─ 02_BOX1_AI_ENRICHMENT.md   (student account ⚠️)
  ├─ 04_BOX3_INTEL_OBSERVABILITY.md
  └─ 05_BOX4_INTERACTSH.md      (Azure Africa VPS)

Phase 6 — Data plane (Day 6-7)
  └─ 06_DO_EPHEMERAL_WORKERS.md — cloud-init + worker binary distribution

Phase 7 — Public access (Day 7)
  └─ 07_DASHBOARD_PUBLIC_ACCESS.md — Cloudflare Tunnel

Phase 8 — Monitoring (Day 7-8)
  └─ Loki/Grafana on Box3 (covered in 04)

Phase 9 — Validation (Day 8)
  └─ 10_SMOKE_TEST.md — full lifecycle scan

Phase 10 — Drill (Day 9)
  └─ 09_INCIDENT_RESPONSE.md — exercise kill-switch
```

Budget 7-10 days for first deploy. Subsequent re-deploys with snapshots: 4 hours.

---

## 5. OPSEC Principles (apply across all runbooks)

1. **No plaintext secrets at rest.** All secrets live in `secrets.env.age` (encrypted to YubiKey-bound identity). Plaintext only ever materialized in `/run/mimikri/secrets.env` tmpfs.
2. **No public IP exposure.** All services bind to `tailscale0` interface only. Public dashboard via Cloudflare Tunnel only.
3. **Ephemeral data plane.** No DO droplet persists > 6 hours. Worker binaries pulled fresh per droplet.
4. **Audit log everything.** `auditd` enabled on all 3 boxes, logs shipped to Box3 Loki. Postgres `log_statement = 'mod'` for write tracking.
5. **Defense in depth.** SSH + Tailscale ACL + iptables + AppArmor + auditd. Single layer failure does not grant target access.
6. **Least privilege + sacrificable tier.** Box1 (student) holds only AI enrichment and paid OCI services — deliberately the *least critical* workloads. Box2 (personal, permanent) is the coordinator. Losing Box1 degrades enrichment; it never stops Bug Bounty scans.
7. **Reproducible.** All config in version control. Box2 destroyed = restore from `age`-encrypted backup + rebuild from runbook in < 4h.
8. **Kill-switch tested.** Ctrl+C on **Box2** destroys all DO droplets in < 30 seconds. Drill quarterly.
9. **Time-bound credentials.** API keys rotated every 90 days. SSH keys never reused across boxes.
10. **No attribution leakage.** Worker traffic never references operator identity (no `User-Agent` strings, no `whois` info on droplets).
11. **Credit posture — active-spend $300 Oracle student credit during the 365-day window, on Box1 only.** No payment method is registered on the Oracle account (credit granted via Oracle for Education / Oracle Academy university linkage), so auto-billing at credit exhaustion is structurally impossible. Credit is spent on Box1 (sacrificable node): Object Storage forensic archive, Block Volume Backup of Box2 via Tailscale, Vulnerability Scanning Service, Logging Analytics retention. **Box2 and Box3 run exclusively on always-free tier — they are unaffected by Box1 credit expiry or email revocation.** Run the day-350 graduation gate (`09_INCIDENT_RESPONSE.md`) to migrate data to Always-Free before paid-tier auto-suspend at day 365.

---

## 6. Operational Cadence

| Frequency | Task | Runbook ref |
|---|---|---|
| Daily | Check Loki for `level=error` + droplet count | `04` |
| Weekly | Verify Postgres replication lag < 5s | `04` |
| Weekly | Review auditd alerts in Grafana | `04` |
| Monthly | `cargo audit` + rebuild worker binary | `06` |
| Monthly | Verify Cloudflare Tunnel cert auto-renewal | `07` |
| Quarterly | Rotate API keys + SSH keys | `08` |
| Quarterly | Kill-switch drill | `09` |
| Quarterly | Restore **Box2** from backup in sandbox | `08` |
| Day 330 of Oracle credit year | Credit-exhaustion warning email arrives — schedule graduation gate | `09` |
| Day 350 of Oracle credit year | Run graduation gate (migrate paid-tier data to Always-Free + local NAS) | `09` |
| Annually | Threat model review | this file |

---

## 7. Glossary

- **Box1/Box2/Box3** — Oracle Cloud ARM VMs (control plane). Each in distinct tenancy. Box1 = student (sacrificable), Box2/Box3 = personal (permanent).
- **Box4** — Azure Africa VPS. Runs `interactsh-server`. Persistent OOB capture node.
- **Coordinator** — Box2. Runs Postgres primary, NATS hub, Dashboard, Sink aggregator, DO spawn controller.
- **Worker** — Ephemeral DO droplet running `redteam_rust_core --worker`, connects to Box2 Postgres.
- **OOB (Out-of-Band)** — Interaction captured by Box4 interactsh when a target makes a callback (DNS/HTTP/SMTP) to a payload the worker injected.
- **Tailnet** — Tailscale virtual private mesh. `100.x.x.x/8` address space. All 4 boxes + workers joined.
- **Kill-switch** — Ctrl+C / SIGTERM on **Box2** coordinator → triggers `destroy_all_ephemeral_droplets()`.
- **Scope** — Authorized target set defined in `policy.json` + `--scope-id`.
- **Campaign** — One scan session with a unique `scope_id`. Maps to one DO droplet pool.

---

## 8. Emergency Contacts (fill in per-operator)

```
Cloudflare account email:       _____________
Cloudflare backup TOTP codes:   stored in: _____________
DigitalOcean account email:     _____________
DigitalOcean backup TOTP:       stored in: _____________
Tailscale admin email:          _____________
Oracle tenancies admin emails:  _____________
HackerOne profile:              _____________
Domain registrar:               _____________
Operator personal email:        _____________
Recovery codes (printed copy):  stored in: _____________ (offline)
```

Keep printed copy in physically secure location (safe / lockbox). Do not store digitally outside YubiKey-protected vault.

---

## 9. Change Control

This runbook is the source of truth. Drift between runbook and live infrastructure is a defect.

- Any infrastructure change MUST be reflected in the corresponding runbook file in the same commit.
- Runbook changes follow standard PR review (Operator approval required for security-sensitive sections: §2, §3.3, §5, §8).
- Mark superseded sections with `> [!DEPRECATED]` rather than deleting — preserves audit history.
