# Stage C Baseline Status — DEGRADED

## Last Attempted Capture
Date: 2026-06-05
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

Do **not** commit a degraded baseline (0 findings + PLUGIN_ERRORs). Keep `golden_baseline.json` at its last known good state (even if stale) until the recovery path is completed.

Future sprint: "Stage C Baseline Recovery" with scope covering tool installation, DNS setup, and policy configuration.
