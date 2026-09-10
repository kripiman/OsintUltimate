# Stage C Baseline Status — DEGRADED (progress, not resolved)

## 2026-09-09 continued: the hang is fixed, root cause confirmed and patched

Found and fixed the real bug from the "reproduced blocker" section below. **BASELINE-HANG-001**:

`src/bin/capture_baseline.rs` built its `memory_semaphore` with a hardcoded `Semaphore::new(1024)`, while separately telling `MemoryMonitor::new(1024, 2048, ...)` the hard limit was `2048`. `dispatch.rs`'s `permits_needed` formula (`dispatch.rs:95-96`) is computed from `memory_monitor.hard_limit_mb()` (2048), not from the semaphore's real capacity — so for any plugin with `cost >= 6` (confirmed to exist: `ssrfmap`, `ssrf_king`, `ghauri`, `deserialization`, `nosqlmap`, `smuggler` are all `TargetType::Web` and eligible for the DVWA target), `permits_needed` (e.g. `6 * 204 = 1224`) exceeds the semaphore's actual 1024-permit ceiling. `Semaphore::acquire_many()` on a request that can *never* be satisfied waits forever — and it's a bare `.await` at `dispatch.rs:99-100` with **no timeout wrapper at all**, unlike the properly-timeout-wrapped `check_dependencies()` (30s) and `scan()` (up to 600s) calls later in the same function. Each such plugin permanently occupies one of the 10 `concurrency_semaphore` slots; enough of them and the whole dispatcher freezes solid with near-zero CPU, no timeout ever firing, and no error logged — exactly what was observed.

Confirmed via `/proc/<pid>` inspection while hung (no `strace`/`gdb` available, no sudo): 38 threads, 37 parked in `futex_wait`, 1 in `ep_poll` — a real block, not a busy-loop, and `utime`/`stime` barely advancing over 235s. This ruled out CPU-bound livelock and pointed at semaphore/channel wait, which the code review then confirmed precisely.

**Note:** `core/orchestrator/mod.rs:23` (the production dispatch path) already does this correctly — `Semaphore::new(hard_limit as usize)`, same value the formula reads. This bug was isolated to `capture_baseline.rs`'s own mismatched hardcoded constant, not a production-path bug.

**Fix applied** (`src/bin/capture_baseline.rs`): `memory_semaphore` is now sized from `memory_monitor.hard_limit_mb()` directly, matching the orchestrator's pattern, so the two values can't diverge again.

**Verified**: re-ran `cargo run --bin capture_baseline` after the fix — it completed in well under 5 minutes (previously: never completed after 900s+), scanning DVWA fully and moving on to Samba, exactly as it should.

### But the resulting baseline is still not "clean" — for a third, different reason
The capture now finishes but only surfaces 2 `PLUGIN_ERROR` findings (`BusinessLogic`, `UploadStrike`), both: `"V14.1 OPSEC Violation: No proxy available for client configuration."` These plugins require a configured `ProxyManager` and correctly refuse to run unproxied rather than leak traffic — that's the stealth infrastructure working as designed, not a bug. But it means this local, no-proxy capture environment still can't produce a fully "real findings" baseline; only a full run through the project's actual stealth/proxy infrastructure would.

**Important**: the *currently committed* `golden_baseline.json` (`f40f7b5`) is **also** degraded — 6 `PLUGIN_ERROR` entries, all `NucleiScanner`/`kiterunner`/`dnsx` failing (×2 each). Those are precisely the plugins now confirmed fixed above (DNS pinning, dnsx whitelist) — none of them fail anymore. So this run's 2-error result, while still not "real findings," is objectively less degraded than what's currently committed and is concrete proof the earlier fixes hold. `golden_baseline.json` in the working tree now holds this new 2-error capture (SHA256 `1527f46177b33c6595b04986ed173cdb7381f9971e82281c2ad03880dc6d1add`) — not committed, left for review.

## Last Attempted Capture (2026-09-09, superseded by the fix above) — supersedes the 2026-06-05 diagnosis below

Actually installed every missing dependency locally (no DO worker was reachable — no `DIGITALOCEAN_TOKEN`/`DATABASE_URL`/interactsh in this environment) and re-ran the capture for real:

- `nuclei`, `httpx`, `naabu`, `dnsx` — installed via `go install` (Go toolchain fetched to `~/.local/go-toolchain`, no root needed).
- `kiterunner` — official repo doesn't `go install` cleanly (needs `go build ./cmd/kiterunner`); built manually, binary placed as `kiterunner` (not `kr`) since that's the name `check_tool_availability` looks for.
- `feroxbuster` via `cargo install`, `sqlmap` via `pip install --user`.
- `docker-compose.test.yml` (lives in `redteam_rust_core/`, not repo root — the old note this file matches "docker-compose.test.yml" didn't say where) brought up DVWA/Samba/NATS; DVWA's `setup.php` database was initialized via its normal POST flow.

**Result with full toolchain present: still 0 findings — but for a different, more serious reason than documented below.**

### The two documented root causes below are stale, not current
Verified directly against current `src/` (2026-09-09), not assumed:
- **"DNS Pinning Violation"** — already fixed. `capture_baseline.rs` sets `resolved_ip: Some(ip)` on both targets, and `TargetHost::pinned_addr()` (`src/models/scan_result.rs:108`) only checks that `resolved_ip.is_some()`. No `/etc/hosts` entry needed.
- **"V14.1 Security Block" on `dnsx`** — already fixed. `dnsx` is in `StaticPolicy`'s default `allowed_binaries` whitelist (`src/core/policy/mod.rs:154`). No policy relaxation needed. (Also: `capture_baseline.rs` already sets `strict_scope = false`, so the separate "no policy.json → fail-closed" scope check is a non-issue too — confirmed via the actual run log: `"Target ... is out of scope but strict_scope is DISABLED. Proceeding with caution."`)

### The real, reproduced blocker: the run hangs indefinitely on the very first target
With every tool installed and both stale issues out of the way, `cargo run --bin capture_baseline` produced zero further log output for 15 straight minutes (killed at my own outer timeout, exit 143) right after `WcdScanner: scanning http://127.0.0.1:8081` started. This is suspicious for a reason beyond "just slow":

- `dispatch.rs` already has a per-plugin hard timeout (`src/core/orchestrator/dispatch.rs:102-108`, added for ticket **ENGINE-TIMEOUT-001**, comment literally says "root cause of Samba:445 20-min hang") capped at 600s, plus a 30s `check_dependencies` timeout (**ENGINE-TIMEOUT-002**).
- 900s > 600s. If that timeout were actually firing, at least one `"Plugin '...' check_dependencies timed out after 30s"` or a scan-timeout warning should have appeared in 15 minutes of log. **None did — total silence.**
- That's consistent with a plugin blocking a tokio worker thread synchronously (not yielding), which would prevent even the timeout timer from ever getting scheduled — the same class of issue flagged elsewhere in this codebase (`native_scanner.rs`'s `ring.submit_and_wait()` inside an async fn without `spawn_blocking`). I did **not** find an obvious synchronous call in `WcdScanner` itself (`src/plugins/enumeration/web/wcd.rs`) on inspection, so the actual stuck plugin/call site is not yet confirmed — could also be semaphore starvation at `dispatch.rs:99-100` (`memory_semaphore`/`concurrency_semaphore` `.acquire()`), which has no timeout wrapper at all.
- **Not yet fixed.** This needs live-process debugging (thread dump / `tokio-console`) to pin the exact stuck call, which is beyond what I did in this pass.

## Original 2026-06-05 attempt (for history)
Command: `cargo run --bin capture_baseline`
Services: DVWA (`127.0.0.1:8081`), Samba (`127.0.0.1:445`), NATS (`127.0.0.1:4222`)
Result: 0 findings captured; all plugins returned PLUGIN_ERROR

## Why Baseline Capture Fails

### 1. DNS Pinning Violation
Plugins `NucleiScanner` and `kiterunner` require a resolved and pinned IP address. The baseline target `127.0.0.1:8081` is a raw IP, but these plugins enforce DNS pinning for rebinding protection. Without a proper DNS record pointing to `127.0.0.1`, they refuse to scan.

Error:
```
DNS Pinning Violation: Nuclei requires a resolved and pinned IP to prevent Rebinding.
DNS Pinning Violation: Kiterunner requires a resolved and pinned IP.
```

### 2. V14.1 Security Block
Plugin `dnsx` fails policy validation. The `SandboxDispatcher` or `ApprovalGate` blocks `dnsx` execution under the baseline configuration.

Error:
```
V14.1 Security Block: Command failed policy validation.
```

### 3. Other Plugins
Most scanner plugins in `get_all_scanners()` are external-tool wrappers (e.g., `nuclei`, `httpx`, `naabu`, `feroxbuster`). These tools are not installed in the baseline execution environment, so they return empty findings or fail dependency checks.

## Recovery Path

To restore a meaningful golden baseline, the following prerequisites must be met:

1. **Install external tools**: `nuclei`, `httpx`, `naabu`, `nmap`, `feroxbuster`, `sqlmap`, etc. must be available in `$PATH`.
2. **Fix target configuration** (done in `capture_baseline.rs`): DVWA should use `TargetType::Web` with `http://127.0.0.1:8081`; Samba uses `TargetType::Host` with `127.0.0.1:445`.
3. **Add per-scan timeouts**: `capture_baseline` runs ~100 scanners against each target without per-scanner timeouts. A single slow scanner can hang the entire baseline for minutes. Add timeout logic or filter scanners to a representative subset.
4. **Configure DNS pinning**: Add a local DNS record (e.g., via `/etc/hosts`) mapping `baseline.local` → `127.0.0.1`, and update scanners that enforce hostname-based pinning.
5. **Relax security policy for baseline**: The `ApprovalGate` and `SandboxDispatcher` policies that block `dnsx` must be configurable to allow baseline scans. Alternatively, run baseline capture with a dedicated `BaselinePolicy` that permits local scanning.
6. **Ensure DVWA is fully initialized**: DVWA requires database setup on first boot. The capture should wait for DVWA to be ready (check `/setup.php`).

## Recommendation

Do **not** commit a degraded baseline (0 findings + PLUGIN_ERRORs). This still applies — the 2026-09-09 recapture (2 `PLUGIN_ERROR`s, proxy-required) is a real improvement over the committed one (6 `PLUGIN_ERROR`s) but is still not "real findings." Left uncommitted in the working tree for review rather than auto-replacing `f40f7b5`.

Remaining for a genuinely clean baseline: run capture through the project's actual stealth/proxy infrastructure (`ProxyManager`) instead of unproxied locally, so proxy-gated plugins (`BusinessLogic`, `UploadStrike`, and likely others) can actually execute.

Future sprint: "Stage C Baseline Recovery" — tool installation and hang-fix are now done (2026-09-09); remaining scope is proxy infrastructure for a full run.
