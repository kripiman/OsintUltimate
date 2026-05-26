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

*(Section placeholder for Stage 11.E — additional rejected tools and re-evaluation triggers)*
