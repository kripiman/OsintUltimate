# Sprint Audit Remediation Handoff — Post-Production Blockers (2026-06-05)

## Closed Blockers (Production Unlocked)

| ID | Finding | Fix | Commit |
|---|---|---|---|
| MEM-002 | `WasmPlugin::name()` leaked on every call | `cached_name: &'static str` leak-once in constructor | `720fd01` |
| MEM-001 | `FFIPluginWrapper` leak-once contract unclear | Documented + interner dedup | `5645a03`, `7492de5` |
| SEC-001 | Unbounded `BTreeMap` in sanitizer | `LruCache<String, String>` (cap 10K) | `30bd2c4` |
| SEC-002 | `ptr::read` without alignment check | `read_unaligned` + SAFETY comment | `140e5e2` |
| PERF-002 | `dotenv` unmaintained | `dotenvy` drop-in replacement | `ccacb01` |
| SEC-004 | `net_evasion` no sandbox in FluidLocal | Spike doc — recommend StrictDocker for net_evasion | `b21f5d6` |
| Arc Refactor | `Box::leak` pattern not future-proof | Name interner — dedup by value, 1 leak per distinct name | `7492de5` |

## Deferred / Debt

| ID | Status | Location |
|---|---|---|
| PERF-001 | Deferred — risk register | `docs/performance/PERF-001_rustls_dup.md` |
| Stage C | DEGRADED — recovery path documented | `tests/baselines/DEGRADED_STATUS.md` |
| once_cell → LazyLock | Deferred — low ROI (~63 usages) | Phase 7 |

## Verification State

- `cargo clippy --all-targets -- -D warnings` → EXIT 0
- `cargo test --lib` → 228 passed; 0 failed; 3 ignored
- No new RED introduced during remediation

## Next Steps

1. **Stage C Baseline Recovery** (optional, 2–4 days): Install external tools, configure DNS pinning, relax baseline policy, re-capture `golden_baseline.json`
2. **PERF-001 rustls unify** (optional, 3–5 days): Trigger when reqwest 0.12 becomes required
3. **once_cell → LazyLock** (optional, Phase 7): Low priority hygiene cleanup
