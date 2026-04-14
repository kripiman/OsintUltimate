# AUDIT REPORT — REDTEAM_RUST_CORE V14.1
**Sovereign Offensive Architecture Audit**
**Auditor**: Antigravity Senior Offensive Architect
**Date**: 2026-04-14
**Scope**: Post-Exploitation Sovereignty, Egress Isolation, Infrastructure Resilience, Systemic Debt
**Evidence Basis**: Direct source code inspection. Zero assumptions. Every claim is traceable to exact file and line.

---

## EXECUTIVE SUMMARY

This is a ground-truth re-audit of the `redteam_rust_core` V14.1 codebase via direct file inspection. The previous `AUDIT_REPORT.md` version contained several **factual inaccuracies** — specifically: over-stating proxy isolation guarantees for `bloodhound.rs`, mis-attributing line ranges, and failing to flag a live `ExploitExecutor` stub and a critical danted misconfiguration. All corrections are documented below with code-level evidence.

The system has made **significant genuine progress** since prior versions. The C2 operators and pivot engine are structurally real — not placeholders. However, three unresolved architectural risks prevent a clean production GO.

---

## [POST-EXPLOIT-SOVEREIGNTY]

### FINDING PSE-001 — VERIFIED ✅: Sliver Payload Delivery via OTT + RemoteExecutor

**File**: `src/plugins/lateral_movement/sliver.rs`, lines 73–103

**Evidence**:
```rust
// Line 79-80: Real PayloadServer instantiation with UUID token
let server = Arc::new(crate::utils::payload_server::PayloadServer::new());
let token = server.stage_payload(std::path::PathBuf::from(payload_path));
let server_port = server.clone().start().await?;

// Line 99: Real remote dispatch via RemoteExecutor trait (not a local stub)
let output = self.executor.execute_remote(target, &delivery_cmd).await?;
```

**Verdict**: VERIFIED. `deploy_payload` is not a placeholder. It instantiates `PayloadServer` over an ephemeral `TcpListener::bind("0.0.0.0:0")` port (confirmed in `utils/payload_server.rs:32`), generates a UUID one-time token, constructs a proper `curl`-based delivery vector, and dispatches it through `StealthExecutor::execute_remote`. Session verification queries the Sliver REST API at `http://{server}:31337/api/sessions` (line 110), with a working CLI fallback.

**Posture Impact (BREACH)**: VALID. C2 lifecycle (Preparation → OTT Staging → Remote Dispatch → REST Verification) is architecturally functional. Real capability, not theater.

**Residual Risk**: `prepare_payload` invokes `sliver-server generate --mtls` via `Command::new` (line 54–64) **without** routing through `StealthExecutor` (no policy check, no `proxychains` wrapping). This is an unconditional local binary call. OPSEC implication: payload generation process metadata (timing, binary name) is unmasked on the operator host. Not critical in a controlled environment, but noteworthy.

---

### FINDING PSE-002 — VERIFIED ✅: Havoc Demon Delivery

**File**: `src/plugins/persistence/havoc.rs`, lines 73–101

**Evidence**:
```rust
// Line 98: Real remote dispatch
let output = self.executor.execute_remote(target, &delivery_cmd).await?;
```

**Verdict**: VERIFIED. Structurally identical to Sliver: `PayloadServer` OTT staging, delivery IP from `pm.get_managed_exits()`, `execute_remote` dispatch. Session list queries `HAVOC_API_URL/api/sessions` (line 118) via a ProxyManager-gated client. CLI fallback parses raw `stdout` lines into `C2Session` structs (lines 141–151) — note that this fallback is intentionally coarse (no field parsing), acceptable as a degraded mode.

**Posture Impact (BREACH)**: VALID.

---

### FINDING PSE-003 — PARTIALLY VERIFIED ⚠️: Ligolo Pivot — Functional but with a OPSEC Gap

**File**: `src/plugins/lateral_movement/ligolo.rs`, lines 50–115

**Evidence**:
```rust
// Line 57: Local proxy spawned via StealthExecutor (correct path)
let _proxy_child = self.executor.spawn(&self.binary_path, vec!["-selfcert"...]).await?;

// Line 67: Agent path is HARDCODED — assumes ligolo-agent is pre-staged on the operator VPS
let agent_path = "/usr/bin/ligolo-agent";

// Line 80: Remote dispatch is real
let _output = self.executor.execute_remote(target, &agent_cmd).await?;

// Lines 85–93: Legitimate polling verification via `ip addr show ligolo`
for i in 0..5 {
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let iface_check = tokio::process::Command::new("ip").arg("addr").arg("show").arg("ligolo").output().await?;
    ...
}
```

**Verdict**: FUNCTIONALLY REAL but with an architectural assumption gap. The `agent_path` is hardcoded to `/usr/bin/ligolo-agent` (line 67), meaning the `PayloadServer` stages this pre-existing local binary. The code comment on lines 63–64 explicitly acknowledges this: *"we assume an established relay or SSH-staged payload on the managed exit."* This is not a placeholder — it is a documented constraint. The operator must pre-deploy `ligolo-agent` on the staging VPS. The verification (polling `ip addr show ligolo`) is a proper confirmation gate.

**Posture Impact (BREACH)**: CONDITIONALLY VALID. Functional if `ligolo-agent` binary is pre-staged on the operator VPS. Fails silently at staging phase if not present (`PayloadServer` will attempt to `tokio::fs::File::open("/usr/bin/ligolo-agent")` and return 404).

**Residual Risk**: The `ip addr show ligolo` command (line 88) is invoked via `tokio::process::Command::new("ip")` — a **direct, unproxied local syscall** appropriate for local interface detection. No OPSEC risk here. However, the `metadata()` block (line 29) has a generic description `"Automated security analysis using this plugin."` — minor hygiene debt.

---

### FINDING PSE-004 — PARTIALLY VERIFIED ⚠️: BloodHound — Missing Proxy Wrap on `execute_and_wait`

**File**: `src/plugins/lateral_movement/bloodhound.rs`, lines 87–119

**Verdict**: **CORRECTION TO PREVIOUS REPORT.** The prior `AUDIT_REPORT.md` stated *"Active Directory collection properly wraps `bloodhound-python` executions natively with `proxy_manager.wrap_command()`."* This is **FALSE by direct inspection.**

**Evidence**:
```rust
// Line 97: bloodhound-python is dispatched via execute_and_wait — NOT via wrap_command directly
let output = self.executor.execute_and_wait(&self.binary_path, args).await?;
```

`StealthExecutor::execute_and_wait` calls `spawn` (line 93 of executor.rs), which **does** call `pm.wrap_command()` internally — but only when `self.stealth_mode || !pm.is_empty()` (executor.rs lines 59–71). The proxy wrapping is therefore **conditional on runtime configuration**, not guaranteed by code structure. If `StealthExecutor` is constructed with `stealth_mode: false` and an empty proxy pool, `bloodhound-python` runs **unproxied**.

**Posture Impact (GHOST/BREACH)**: CONDITIONAL. The proxy wrapping is architecturally present but not enforced at the plugin level. A misconfigured deployment can leak AD collection metadata without warning.

**Ingestion Pipeline**: VERIFIED REAL. `ingest_results()` (lines 23–56) reads BloodHound JSON output files from the current directory and routes them into `CorrelationEngine` via `AdIngestor`. File matching (users.json, computers.json, groups.json, edges.json, etc.) is explicit and correct.

---

### FINDING PSE-005 — CRITICAL FLAG 🔴: `ExploitExecutor` is a Hard Stub

**File**: `src/core/validation/remote.rs`, lines 63–74

**Evidence**:
```rust
pub struct ExploitExecutor { }

#[async_trait]
impl RemoteExecutor for ExploitExecutor {
    async fn execute(&self, target: &TargetHost, _cmd: &str) -> Result<String> {
        // TODO: Implement bridge to PocValidator to re-run successful RCE exploits
        anyhow::bail!("ExploitExecutor not yet implemented for target {}", target.host)
    }
}
```

**Verdict**: `ExploitExecutor` always fails at runtime. Any code path that supplies an `ExploitExecutor` as the `remote_executor` in `StealthExecutor` will produce an unconditional error. The C2 operators (Sliver, Havoc, Ligolo) all depend on `execute_remote` → `remote_executor`. If the integrator wires `ExploitExecutor` instead of `SshExecutor`, the entire BREACH posture collapses silently.

**Posture Impact (BREACH)**: **CRITICAL RISK**. This is not a blocker if `SshExecutor` is correctly wired at initialization, but the dead stub creates a dangerous failure mode with no compile-time enforcement. The `StealthExecutor` accepts `Option<Arc<dyn RemoteExecutor>>`, meaning `None` is also valid — and will bail at runtime with an unhelpful message.

**Recommendation**: Remove `ExploitExecutor` or replace with a `#[cfg(debug_assertions)]` guard. The `remote_executor: Option<...>` field in `StealthExecutor` should become non-optional for any BREACH-posture deployment mode.

---

## [STEALTH-SOVEREIGNTY]

### FINDING SS-001 — VERIFIED ✅: Fail-Closed Egress for AI/API Providers

**Files**: `src/core/ai/openai.rs` (lines 19–25), `src/core/ai/gemini.rs` (lines 21–27)

**Evidence**:
```rust
// openai.rs:21-23
let pm = self.proxy_manager.as_ref()
    .context("V13 OPSEC Violation: OpenAIClient requires an active ProxyManager...")?;
let (_, client) = pm.get_client_fail_closed("api.openai.com")?;
```

**Verdict**: VERIFIED. `get_client_fail_closed` (proxy.rs:403–406) calls `get_client()` and returns `Err` if no proxy is available — not a bare network request. Both `OpenAIClient` and `GeminiClient` will abort with a hard error rather than leak origin IP. This is correct fail-closed behavior. `DigitalOceanClient::get_client()` (digital_ocean.rs:102) also uses `get_client_fail_closed("api.digitalocean.com")`.

**Posture Impact (GHOST)**: ZERO-LEAK VERIFIED for all HTTP/reqwest egress paths.

---

### FINDING SS-002 — VERIFIED ✅: Sovereign Handover HALT Gate

**File**: `src/core/validation/sovereign.rs`, lines 31–51; `src/core/validation/mod.rs`, lines 57–59

**Evidence**:
```rust
// mod.rs:58-59 — Bifurcation point: complexity >= 70 triggers halt
if poc.complexity_score >= 70 {
    return self.sovereign_handover(finding, target, &poc).await;
}

// sovereign.rs:35 — Blocks thread on approval
let req_id = self.approval_gate.request_approval(...).await?;

// sovereign.rs:38 — Waits up to 1200s (20 min) for external operator input
if self.approval_gate.wait_for_approval(&id, 1200).await { ... }

// sovereign.rs:42-44 — Only executes if operator supplies handover_payload
let output = self.execute_raw_payload(payload, target).await?;
```

**Verdict**: VERIFIED. The HALT mechanism is structurally sound. The `ApprovalGate::wait_for_approval` is a blocking gate — execution does not proceed without an explicit `Approved { handover_payload: Some(...) }` from the operator. The 1200-second timeout is appropriately long for human-in-the-loop workflows.

**Posture Impact (STRIKE)**: SAFE. Zero autonomous deep infection. The gate is not bypassed for `poc.complexity_score < 70` cases, but those cases still require `approval_gate.request_approval` for intrusive PoCs (mod.rs lines 63–79).

---

### FINDING SS-003 — VERIFIED ✅: `wrap_command` Proxychains Integration

**File**: `src/utils/proxy.rs`, lines 297–323; `src/utils/executor.rs`, lines 59–71

**Evidence**:
```rust
// proxy.rs:299: Fails hard if no SOCKS5 available
pub fn wrap_command(&self, tool: &str, args: &mut Vec<String>) -> Result<()> {
    if let Some(proxy_url) = self.get_best_socks_url() {
        match tool {
            "curl" => { args.insert(0, "-x"...); }
            "nmap" => { args.push("--proxies"...); }
            _ => { args.insert(0, tool.to_string()); } // proxychains4 mode
        }
        Ok(())
    } else {
        anyhow::bail!("V13 OPSEC Violation: No proxy available for command wrapping.")
    }
}
```

**Verdict**: VERIFIED. The `wrap_command` function correctly fails if no SOCKS5 exit is available. The `StealthExecutor::spawn` honoring this path is conditional on `stealth_mode` flag (see PSE-004 caveat). The proxychains mode inserts the original tool name as `args[0]` and switches the binary to `proxychains4` — this is standard `proxychains-ng` protocol.

**Posture Impact (GHOST)**: VALID when `stealth_mode: true` is set at construction.

---

## [INFRA-RESILIENCE]

### FINDING IR-001 — PARTIALLY RESOLVED ⚠️: DigitalOcean Danted Config — Open Relay Risk Persists

**File**: `src/infrastructure/digital_ocean.rs`, lines 54–86

**Previous Report Claim**: *"Deployments correctly inject locally generated operator passwords applying a valid `method: username`."*

**Reality (direct inspection of `generate_proxy_user_data`, lines 54–86)**:

```yaml
# Lines 65-66 — socksmethod IS set to username ✅
socksmethod: username

# BUT lines 69–73 — client pass block uses method: NONE ❌
client method: none
client pass {
    from: 0.0.0.0/0
    to: 0.0.0.0/0
}

# Lines 75–79 — socks pass block has NO method override
socks pass {
    from: 0.0.0.0/0
    to: 0.0.0.0/0
    protocol: tcp udp
}
```

**Verdict**: **OPEN RELAY RISK PERSISTS.** The global `socksmethod: username` is set, but the `client pass` block explicitly uses `method: none` — which overrides authentication for the client-handshake phase in Dante. The `socks pass` block does not specify `method: username` explicitly, relying on the global setting. In Dante, the block-level `method` directive overrides the global one. The `client pass { method: none }` line creates an unauthenticated client acceptance path.

The password generation itself (`uuid::Uuid::new_v4().to_string()[..12]`, line 118) is correct, and `useradd`/`chpasswd` runcmds are valid. The flaw is in the danted rule structure, not the password entropy.

**Posture Impact (GHOST)**: MEDIUM-HIGH RISK. The ephemeral droplet may function as an open SOCKS5 relay accessible to any external scanner on port 1080, compromising operator OPSEC by associating the relay's IP with scanning activity not under operator control.

**Remediation**: Fix `generate_proxy_user_data`:
```yaml
client pass {
    from: 0.0.0.0/0
    to: 0.0.0.0/0
    socksmethod: username   # ← add this
}
socks pass {
    from: 0.0.0.0/0
    to: 0.0.0.0/0
    protocol: tcp udp
    socksmethod: username   # ← add this
}
```

---

### FINDING IR-002 — VERIFIED ✅: ProxyManager Fail-Closed Architecture

**File**: `src/utils/proxy.rs`, lines 403–406, 524–527

**Verdict**: VERIFIED. `is_empty()` gates on both `lock_proxies().is_empty() && managed_exits.is_empty()`. `get_client_fail_closed` wraps `get_client` with an error if the pool is empty. No fallback to bare network access exists. `wait_for_readiness` (lines 530–544) provides an explicit readiness gate with configurable timeout.

---

## [SYSTEMIC-DEBT]

### FINDING SD-001 — ACTIVE ⚠️: ~153 Compiler Warnings

**Verdict**: Confirmed from `check_errors.txt` (32,960 bytes). Predominantly unused imports (`std::process::Stdio`, `Command`) orphaned after migration to `StealthExecutor`. No runtime or security implication, but dead code increases attack surface analysis time.
**Recommendation**: `cargo fix --lib -p redteam_rust_core` followed by targeted `#[allow(unused_imports)]` suppressions for intentional stubs.

---

### FINDING SD-002 — ACTIVE ⚠️: Generic Plugin Metadata in Ligolo and BloodHound

**Files**: `ligolo.rs:29`, `bloodhound.rs:66`

**Evidence**:
```rust
description: "Automated security analysis using this plugin.".to_string(),
```

Both plugins carry a copy-paste default description. This is cosmetic debt that will cause confusion in auto-generated operator reports. `mitre_attacks: vec![]` on both is also incomplete.

---

### FINDING SD-003 — ACTIVE ⚠️: `NucleiTemplate` PoC Strategy is Unimplemented

**File**: `src/core/validation/mod.rs`, line 87

**Evidence**:
```rust
PocStrategy::NucleiTemplate => Ok("Estrategia Nuclei pendiente de integración.".to_string()),
```

Any finding with `PocStrategy::NucleiTemplate` will return a pseudo-success string that never actually runs Nuclei. This is a silent false positive in the pipeline. The `expected_pattern` check will pass if the pattern is a substring of that hardcoded string.

---

### FINDING SD-004 — ACTIVE ⚠️: `prepare_payload` in Sliver/Havoc Bypasses StealthExecutor

**Files**: `sliver.rs:54–64`, `havoc.rs:52–64`

**Evidence**:
```rust
// sliver.rs:54 — raw tokio::process::Command, not self.executor.spawn()
let mut child = Command::new(&self.binary_path);
child.arg("generate").arg("--mtls")...
```

The implant generation step calls the `sliver-server`/`havoc` binary directly via `tokio::process::Command`, bypassing `StealthExecutor`'s policy check and proxy wrapping. This means:
1. No policy validation (tool not in blackarch allowlist).
2. No `proxychains4` wrap applied to the generation subprocess.
3. No `env_clear()` applied (process inherits full operator environment variables).

**Posture Impact (OPSEC/BREACH)**: LOW in air-gapped TrafficServer scenarios, MEDIUM in operator environments where the C2 server is internet-facing.

---

## 🎖️ COLD TRUTH ASSESSMENT — PRODUCTION READINESS SCORE

### Component-Level Assessment (V14.1 Ground-Truth)

| Component | Score | Notes |
|---|---|---|
| **Egress/Proxy Isolation (reqwest)** | 9.0/10 | `get_client_fail_closed` is genuine. Fail-closed for all AI/DO APIs. |
| **Sliver / Havoc C2 Operators** | 7.5/10 | OTT staging and `execute_remote` are real. `prepare_payload` bypasses executor (-1.0). `ExploitExecutor` stub is a silent failure bomb (-0.5). |
| **Ligolo Pivot** | 7.0/10 | Real process execution and tunnel verification. Hardcoded `/usr/bin/ligolo-agent` path is a deployment constraint, not a placeholder. Metadata is stale. |
| **BloodHound Integration** | 7.5/10 | `execute_and_wait` path through `StealthExecutor` is real but proxy-wrapping is configuration-conditional, not guaranteed. Ingestion pipeline is verified real. |
| **PocValidator / Sovereign Gate** | 8.5/10 | HALT and handover mechanisms are structurally sound. `NucleiTemplate` strategy is a silent false-positive bug. |
| **DigitalOcean Ephemeral Proxies** | 5.5/10 | Password generation is sound; danted config has a structural open-relay risk that was not caught in the prior audit. |
| **StealthExecutor Architecture** | 8.0/10 | Policy-first, env-cleared spawn, proxychains wrapping. `Option<RemoteExecutor>` is an unsafe default. |

---

### FINAL VERDICT

> **OVERALL SCORE: 7.5 / 10.0**
> *Classification: Operational Red Team Platform — Pre-Production Hardening Required*
>
> Delta correction from prior inflated score: **-1.3 points** (factual re-assessment).

**Conclusion**: **🟡 CONDITIONAL GO — Requires 3 targeted fixes before sovereign production deployment.**

The system is **not** a vulnerability scanner cosplaying as a C2 operator. The core post-exploitation machinery is real and functional. However, three blockers must be resolved before a clean GO:

1. **[IR-001] Fix danted configuration** — Add `socksmethod: username` to `client pass` and `socks pass` blocks. Without this, every ephemeral proxy node is an open relay.
2. **[PSE-005] Remove or gate `ExploitExecutor`** — The stub creates silent, untraceable BREACH failures. Make `remote_executor` non-optional in BREACH mode, or add a compile-time feature gate.
3. **[SD-003] Fix `NucleiTemplate` silent false-positive** — Return `Err(...)` or `Ok(false)` instead of a pseudo-success string. This corrupts the finding verification pipeline.

Remaining items (SD-001, SD-002, SD-004) are operational debt, not blockers.
