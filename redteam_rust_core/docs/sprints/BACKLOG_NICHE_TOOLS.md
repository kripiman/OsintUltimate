# Backlog — Niche Tools & Deferred Integrations

**Created**: Sprint 11 (2026-05-26)  
**Owner**: Operator (gabriel) + Auditor (wenyan-ultra mode)  
**Purpose**: Record tools evaluated, rejected, or conditionally deferred during Mimikri V14.3 development. Prevents re-evaluation churn by documenting quantitative rationale.

---

## Noseyparker (Secret Scanner)

**Status**: Deferred — conditional install only.  
**Decision Date**: 2026-05-26

### Comparison: TruffleHog (present) vs Noseyparker

| Criterion | TruffleHog | Noseyparker | Winner |
|---|---|---|---|
| Filesystem scan | ✅ | ✅ | Tie |
| GitHub repo scan | ✅ (`trufflehog github --repo`) | ✅ | Tie |
| Parallel engine | `--concurrency` (default 8) | Multi-thread + bloom filter | Noseyparker |
| Monorepo (>1M commits) | Slow (hours) | Fast (minutes) | Noseyparker |
| Verified mode | ✅ (`--only-verified`) | ❌ (no verifiers) | TruffleHog |
| Maintenance | Active (Truffle Security) | Active (Praetorian) | Tie |
| Binary size in DO image | ~30MB¹ | ~80MB¹ | TruffleHog |

¹ *Source: GitHub releases page (trufflesecurity/trufflehog v3.x amd64-linux ≈ 30MB; praetorian-inc/noseyparker v0.x amd64-linux ≈ 80MB)*

### Rationale

1. **Verified mode is critical for bug bounty**: TruffleHog's `--only-verified` reduces false positives by testing credentials live. Noseyparker lacks verifiers; every hit would require manual validation.
2. **Binary size cost**: +50MB in the DO ephemeral worker image for a tool that runs in <1% of scans (monorepo edge case).
3. **TruffleHog covers 99% of scopes**: For targets <500K commits, TruffleHog performance is acceptable.

### Conditional Install Criteria

Noseyparker MAY be installed manually when **ALL** of the following are true:

- Target scope explicitly includes a Git repository with >500K commits *(heuristic threshold — empirical re-tune after first monorepo scan)*
- TruffleHog scan time is measured >30 minutes for the repo
- Operator accepts the lack of verified mode (manual validation required)
- Disk space budget allows +80MB binary

### Re-evaluation Trigger

Revisit this decision if:

- Noseyparker adds verified-mode equivalent (track: https://github.com/praetorian-inc/noseyparker)
- TruffleHog removes verified mode or becomes unmaintained
- Monorepo targets become >50% of scan volume

---

## Credential Leak Validation — Rejected Alternatives

*Pricing snapshot 2026-05-26 (verify at time-of-decision via vendor pricing page).*

### Dehashed
**Status**: Rejected.  
**Cost**: $5.49/mo minimum ($66/yr).  
**Reason**: Paid mandatory. Coverage overlap with HIBP + IntelX = ~80%. Marginal value vs free tier already implemented (h8mail + HIBP Pwned Passwords + HIBP Breached Account).  
**Re-evaluation trigger**: If Dehashed offers free tier ≥ 2027-Q1.

### Snusbase
**Status**: Rejected.  
**Cost**: $20/mo ($240/yr).  
**Reason**: Same coverage as h8mail free chain. Cost disproportionate to incremental value.  
**Re-evaluation trigger**: If price drops below $5/mo or free tier introduced.

### Self-hosted Collection #1-5 Torrent
**Status**: Rejected.  
**Cost**: $0 (torrent).  
**Reason**: 150GB storage requirement; legal grey area in multiple jurisdictions; OPSEC liability for bug bounty operators.  
**Re-evaluation trigger**: Never — legal risk is a hard block.

### Hunter.io
**Status**: Rejected.  
**Cost**: Free tier 25 searches/mo.  
**Reason**: Email enumeration, not leak validation. Wrong scope for CredentialLeakScanner.  
**Re-evaluation trigger**: If Hunter.io adds breach correlation API.

---

## Intelligence / Recon — Rejected & Deferred

### Censys Integration
**Status**: Rejected.  
**Reason**: Free tier deprecated 2024. Paid only. Redundant with Shodan (already integrated) + FOFA (optional).  
**Re-evaluation trigger**: If Censys reintroduces free tier ≥ 500 req/mo.

### BinaryEdge
**Status**: Rejected.  
**Reason**: Free tier reduced to 250 req/mo — marginal utility. Coverage overlap with Shodan.  
**Re-evaluation trigger**: If free tier restored to ≥ 1000 req/mo.

### Shodan Monitor API (Live Push)
**Status**: Deferred — Sprint 12+ candidate.  
**Decision review deadline**: 2026-12-31.  
**Cost**: $69/mo.  
**Reason**: Useful for continuous monitoring (cert/IP change alerts), but violates zero-cost bias for default pipeline.  
**Re-evaluation trigger**: If Shodan Monitor included in Shodan membership tier or price drops below $20/mo.
