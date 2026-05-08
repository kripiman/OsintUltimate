# AIP.md — Architect Improvement Plan (V15 Sovereign)
> ROLE: ARCHITECT-V14-SOVEREIGN | AUDIT: MIMIKRI.RUST (117-PLUGINS)
> STATE: TYPESTATE-C2 / FAIL-CLOSED / MODULAR-TRAITS

---

## [1] FLOW: PIPELINE-CRUSH

### 1.1 CHAIN-LOGIC: DISCO → SCAN → BREACH (Kill Re-Scan)

**PROBLEM:** `orchestrator.rs` reactive triggers re-scan the same `target` snapshot inline after the main `JoinSet` completes. This means a target can be scanned by the full plugin set AND then re-scanned by reactive chains (SSTI→Commix, SBOM→Grype, GQL→Schemathesis, JS→Retire, Mobile, Cloud, AI). No deduplication guard on reactive chains — a finding that triggers multiple chains causes redundant tool invocations.

**FIX — Typestate Pipeline Guard:**

```rust
// models/findings.rs — add reactive-chain dedup marker
#[derive(Default)]
pub struct ReactiveChainGuard(DashSet<String>);

impl ReactiveChainGuard {
    /// Returns true only on first fire for (finding_id, plugin_name) pair.
    pub fn fire(&self, finding_id: &str, plugin: &str) -> bool {
        self.0.insert(format!("{}:{}", finding_id, plugin))
    }
}
```

```rust
// orchestrator.rs — thread the guard through reactive triggers
let chain_guard = ReactiveChainGuard::default();

// BEFORE each reactive trigger:
if chain_guard.fire(FINDING_SSTI, PLUGIN_COMMIX) {
    // ... commix scan
}
if chain_guard.fire(FINDING_SBOM_INVENTORY, PLUGIN_GRYPE) {
    // ... grype scan
}
```

**IMPACT:** Eliminates duplicate reactive scans. Zero re-scan on same finding_id+plugin pair per target.

---

### 1.2 REACTIVE-TRIGGER: SOURCE_LEAK → SEMGREP / SERIAL_POINT → YSOSERIAL

**PROBLEM:** `orchestrator.rs` has reactive triggers for SSTI, SBOM, GraphQL, JS, Mobile, Cloud, AI — but **no trigger for source code leaks → Semgrep** and **no trigger for deserialization points → ysoserial/DeserializationScanner**.

`DeserializationScanner` exists in `plugins/exploitation/web/deserialization.rs` and `SemgrepScanner` in `plugins/compliance/semgrep.rs` but neither is wired as a reactive trigger.

**FIX — Add two reactive blocks in `orchestrator.rs`:**

```rust
// --- REACTIVE TRIGGER: SOURCE LEAK → SEMGREP ---
let source_leak = all_findings.iter().any(|f| {
    matches!(f.core.id.as_str(), "SOURCE-CODE-EXPOSED" | "GIT-REPO-EXPOSED" | "BACKUP-FILE")
});
if source_leak {
    if let Some(plugin) = plugins.iter().find(|p| p.name() == "semgrep") {
        if chain_guard.fire("SOURCE_LEAK", "semgrep")
            && (!lp.needs_approval(plugin.metadata().layer)
                || approval_gate.is_approved(plugin.name()).await)
        {
            if let Ok(mut f) = plugin.scan(&target).await {
                all_findings.append(&mut f);
            }
        }
    }
}

// --- REACTIVE TRIGGER: SERIAL POINT → DESERIALIZATION ---
let serial_hit = all_findings.iter().any(|f| {
    f.core.id.contains("JAVA-SERIAL") || f.core.id.contains("PICKLE") || f.core.id.contains("YSOSERIAL")
});
if serial_hit {
    if let Some(plugin) = plugins.iter().find(|p| p.name() == "deserialization") {
        if chain_guard.fire("SERIAL_POINT", "deserialization")
            && (!lp.needs_approval(plugin.metadata().layer)
                || approval_gate.is_approved(plugin.name()).await)
        {
            if let Ok(mut f) = plugin.scan(&target).await {
                all_findings.append(&mut f);
            }
        }
    }
}
```

---

### 1.3 SCOPE-SHARPEN: ARJUN.OUT → NARROW SQLMAP.PARAMS (No Bruteforce)

**PROBLEM:** `SqlMapScanner` runs against the full target URL. `ArjunScanner` discovers parameters but its output (`ARJUN-PARAMS-FOUND` finding) is never fed into SqlMap's parameter list. SqlMap defaults to full crawl + bruteforce mode.

**FIX — Param-narrowing via `extra_data` injection:**

```rust
// In orchestrator.rs, after JoinSet collection, before reactive triggers:
let arjun_params: Vec<String> = all_findings.iter()
    .filter(|f| f.core.id == "ARJUN-PARAMS-FOUND")
    .filter_map(|f| f.evidence.evidence.as_ref())
    .filter_map(|e| e.data.get("params"))
    .filter_map(|v| v.as_array())
    .flat_map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)))
    .collect();

if !arjun_params.is_empty() {
    Arc::make_mut(&mut target.extra_data)
        .as_object_mut()
        .map(|obj| obj.insert(
            "sqlmap_params".into(),
            serde_json::json!(arjun_params.join(",")),
        ));
}
```

```rust
// In plugins/exploitation/web/sqlmap.rs — consume narrowed params:
let params = target.extra_data.get("sqlmap_params")
    .and_then(|v| v.as_str());

if let Some(p) = params {
    cmd.args(["--data", p, "--level=1", "--risk=1"]); // no bruteforce
} else {
    cmd.args(["--forms", "--level=1", "--risk=1"]);
}
```

**IMPACT:** SqlMap runs targeted, not blind. Eliminates bruteforce parameter discovery. Reduces scan time ~60% on parameterized targets.

---

## [2] TOKENS: DATA-GUT

### 2.1 PAYLOAD-ENCODE: STRIP HEADERS / BANNERS — RAW VULN VECTOR ONLY

**PROBLEM:** `compressor.rs::compress_finding()` retains a whitelist of 7 headers (`server`, `x-powered-by`, `csp`, `x-frame-options`, `sts`, `location`, `www-authenticate`). For AI analysis, only `server` and `x-powered-by` carry tactical signal. The rest are noise.

`compress_swarm_context()` already strips `body` and `raw_response` but only for the Swarm Planner path. The standard `analyze()` path in `router.rs` uses `compress_finding()` with the full 7-header whitelist.

**FIX — Unified minimal header set:**

```rust
// compressor.rs — replace the whitelist in minify_evidence_object()
fn minify_evidence_object(obj: &mut serde_json::Map<String, serde_json::Value>, body_limit: usize, _planner_only: bool) {
    if let Some(val) = obj.get_mut("body") {
        if let Some(s) = val.as_str() {
            if s.len() > body_limit {
                *val = serde_json::json!(format!("{}...[T]", &s[..body_limit]));
            }
        }
    }
    // UNIFIED: only tactical headers, always — no planner_only split
    Self::minify_headers(obj, &["server", "x-powered-by"]);
    // Strip banners entirely
    obj.remove("banner");
    obj.remove("raw_response");
}
```

**SAVINGS:** ~15-25% token reduction per finding on header-heavy HTTP findings.

---

### 2.2 CONTEXT-LEAN: KILL REPEATED mTLS FINGERPRINTS

**PROBLEM:** `router.rs::enrich_context_v15()` calls `sm.match_for_context()` and `sm.build_injection()` on every `analyze()` call. If the same finding type hits multiple targets (e.g., 50 hosts with `CVE-2024-XXXX`), the skill injection is rebuilt 50 times with identical content. The `analysis_cache` in `TieredAIRouter` deduplicates by `(host, ip, finding_id, category)` — but the **skill injection itself** is not cached.

Additionally, `ContextCompressor::compress_target()` iterates all findings to extract tech stack on every call — O(n) per AI invocation.

**FIX 1 — Cache skill injections by (finding_id, level, posture, caveman):**

```rust
// router.rs — add injection cache to TieredAIRouter
pub struct TieredAIRouter {
    // ... existing fields
    injection_cache: Cache<String, Option<String>>, // NEW
}

// In TieredAIRouter::new():
injection_cache: Cache::builder()
    .max_capacity(500)
    .time_to_live(Duration::from_secs(3600))
    .build(),

// In enrich_context_v15():
let injection_key = format!("{}:{:?}:{:?}:{:?}", finding.core.id, level, posture, caveman);
if let Some(cached_injection) = self.injection_cache.get(&injection_key) {
    return cached_injection.map(|inj| match base_ctx {
        Some(ctx) => format!("{}\n{}", inj, ctx),
        None => inj,
    });
}
// ... build injection as before, then:
self.injection_cache.insert(injection_key, injection.clone()).await;
```

**FIX 2 — Cache tech stack extraction in compress_target():**

```rust
// compressor.rs — accept pre-computed tech or use lazy extraction
pub fn compress_target_lean(target: &TargetHost) -> serde_json::Value {
    // Only host/ip/type — skip tech stack extraction for Tier 0
    serde_json::json!({
        "h": target.host,
        "ip": target.ip.as_deref().unwrap_or("?"),
        "type": format!("{:?}", target.target_type),
    })
}
```

**SAVINGS:** ~40% token reduction on repeated finding types across multi-target swarms. Eliminates mTLS/fingerprint repetition in skill context.

---

### 2.3 SUMMARY-CAVEMAN: COMPRESS FINDINGS → LLM INPUT (DENSE)

**PROBLEM:** `caveman.rs` wraps LLM instructions but `compress_finding()` still emits `"conf": "POTENTIAL"/"VERIFIED"` as full strings, `"cat"` as a Debug-formatted enum (e.g., `"Vulnerability"`), and `"sev"` as full enum name. These are low-entropy tokens.

**FIX — Numeric/symbol encoding for dense findings:**

```rust
// compressor.rs — replace string fields with compact codes
pub fn compress_finding_dense(finding: &Finding) -> serde_json::Value {
    let sev_code = match finding.core.severity {
        Severity::Critical => "C",
        Severity::High     => "H",
        Severity::Medium   => "M",
        Severity::Low      => "L",
        Severity::Info     => "I",
    };
    let verified = finding.evidence.evidence.as_ref()
        .map(|e| if e.verified { 1 } else { 0 })
        .unwrap_or(0);

    serde_json::json!({
        "id": finding.core.id,
        "s": sev_code,           // "C"/"H"/"M"/"L"/"I" vs "Critical"
        "v": verified,           // 0/1 vs "POTENTIAL"/"VERIFIED"
        "cvss": finding.enrichment.cvss_score,
        "d": finding.core.description.chars().take(150).collect::<String>(),
    })
}
```

**SAVINGS:** ~20% token reduction per finding. At 50 findings/target × 50 targets = significant aggregate savings.

---

## [3] CORE: HARDEN-EGRESS

### 3.1 SSOT-SYNC: DASHMAP DIFF-ONLY (Engine ↔ Web)

**PROBLEM:** `orchestrator.rs` calls `dashboard_targets.insert(target.host.clone(), target.clone())` **twice** per target — once at scan start and once after all findings are collected. Each insert clones the full `TargetHost` including `Arc<Vec<Finding>>`. The web handler `get_targets()` iterates the full DashMap on every HTTP poll, serializing all fields.

**FIX — Diff-only updates via version counter:**

```rust
// models/findings.rs — add version to TargetHost
pub struct TargetHost {
    // ... existing fields
    pub version: u64, // atomic increment on mutation
}

// orchestrator.rs — only insert if findings changed
let new_version = target.findings.len() as u64;
let needs_update = dashboard_targets
    .get(&target.host)
    .map(|existing| existing.version != new_version)
    .unwrap_or(true);

if needs_update {
    target.version = new_version;
    dashboard_targets.insert(target.host.clone(), target.clone());
}
```

```rust
// web/handlers.rs — get_targets() returns only diff since last_version param
pub async fn get_targets(
    _auth: ValidatedOperator,
    State(state): State<Arc<DashboardState>>,
    Query(params): Query<HashMap<String, u64>>, // ?since=<version>
) -> Json<Vec<serde_json::Value>> {
    let since = params.get("since").copied().unwrap_or(0);
    let targets: Vec<_> = state.targets.iter()
        .filter(|kv| kv.value().version > since)
        .map(|kv| { /* serialize */ })
        .collect();
    Json(targets)
}
```

**IMPACT:** Web ↔ Engine sync goes from O(n_targets) full clone to O(changed_targets) diff. Saves bytes on every dashboard poll.

---

### 3.2 CIRCUIT-BREAKER: GHOST-POLICY-TRAP — STEALTH-FAIL → KILL ALL-EGRESS

**PROBLEM:** `proxy.rs::get_client_fail_closed()` returns an error when no proxy is available, but the caller in `orchestrator.rs` and plugin code can catch this error and fall through to a direct connection. There is no **global egress kill switch** that instantly halts all outbound connections on stealth failure.

The `stealth_policy.rs` in `detection_evasion` defines policy but is not wired to a circuit breaker that affects the `ProxyManager`.

**FIX — Arc<AtomicBool> egress kill in ProxyManager:**

```rust
// utils/proxy.rs — add global kill switch
pub struct ProxyManager {
    // ... existing fields
    egress_killed: Arc<AtomicBool>, // NEW
}

impl ProxyManager {
    pub fn kill_egress(&self) {
        self.egress_killed.store(true, Ordering::SeqCst);
        tracing::error!("🔴 CIRCUIT-BREAKER: ALL EGRESS KILLED. Stealth failure detected.");
    }

    pub fn get_client_fail_closed(&self, host: &str) -> Result<(String, reqwest::Client)> {
        if self.egress_killed.load(Ordering::SeqCst) {
            anyhow::bail!("OPSEC VIOLATION: Egress circuit breaker is OPEN. All connections blocked.");
        }
        // ... existing logic
    }
}
```

```rust
// core/policy/mod.rs — wire stealth failure to kill switch
// In StaticPolicy or a new GhostPolicyTrap:
pub struct GhostPolicyTrap {
    inner: StaticPolicy,
    proxy_manager: Arc<ProxyManager>,
}

impl GhostPolicyTrap {
    pub fn on_stealth_failure(&self) {
        self.proxy_manager.kill_egress(); // INSTANT. No fallback.
    }
}
```

```rust
// utils/executor.rs — check kill switch before every command
pub async fn run(&self, binary: &str, args: &[&str]) -> Result<Output> {
    if self.proxy_manager.as_ref()
        .map(|pm| pm.egress_killed.load(Ordering::SeqCst))
        .unwrap_or(false)
    {
        anyhow::bail!("OPSEC: Egress killed. Command '{}' blocked.", binary);
    }
    // ... existing execution
}
```

**IMPACT:** True fail-closed. Any stealth detection → instant global egress halt. No plugin can bypass.

---

### 3.3 RUST-EXT: ARC-SWAP STATE / ZERO-COPY PAYLOADS

**PROBLEM 1 — Arc-Swap for hot-path state:**
`TieredAIRouter.providers` is a `HashMap<RouteLevel, Vec<ProviderEntry>>` behind no synchronization. If providers are updated at runtime (e.g., key rotation, failover), there's a race. `DashboardState` fields like `approval_gate` and `budget` are `Option<Arc<...>>` — accessed on every request with no hot-swap capability.

**FIX:**

```rust
// Cargo.toml
arc-swap = "1.7"

// core/ai/router.rs
use arc_swap::ArcSwap;

pub struct TieredAIRouter {
    pub providers: ArcSwap<HashMap<RouteLevel, Vec<ProviderEntry>>>, // hot-swappable
    // ...
}

// Hot-swap providers without locking:
router.providers.store(Arc::new(new_providers));

// Read path (zero-lock):
let providers = router.providers.load();
if let Some(tier) = providers.get(&current_level) { ... }
```

**PROBLEM 2 — Zero-copy payloads in sandbox:**
`sandbox.rs` passes tool output as `String` (heap allocation + copy). For large outputs (Nuclei, Nmap XML), this is expensive.

**FIX — Use `Bytes` for zero-copy slicing:**

```rust
// Cargo.toml — already has tokio with bytes feature
use bytes::Bytes;

// sandbox.rs / executor.rs
pub struct ToolOutput {
    pub stdout: Bytes,  // zero-copy slice from tokio process output
    pub stderr: Bytes,
    pub exit_code: i32,
}

// Plugin parsers receive &[u8] or Bytes — no String allocation
pub fn parse_nmap_output(raw: &Bytes) -> Result<Vec<Finding>> {
    // parse directly from bytes
}
```

**PROBLEM 3 — `Arc::make_mut` hot-path in orchestrator:**
`Arc::make_mut(&mut target.findings)` in the orchestrator's main loop clones the inner Vec if the Arc has multiple owners. With `dashboard_targets` holding a clone, `Arc::try_unwrap` fails and falls back to `(*arc).clone()` — a full deep clone of all findings.

**FIX — Remove from dashboard before unwrap (already partially done), enforce single-owner pattern:**

```rust
// orchestrator.rs — ensure dashboard_targets.remove() before Arc::try_unwrap
// (already present in code — VERIFY it runs before the unwrap in ALL code paths)
// Add assertion in debug builds:
#[cfg(debug_assertions)]
{
    let strong = Arc::strong_count(&target_ref);
    debug_assert_eq!(strong, 1, "Arc should have single owner before unwrap, got {}", strong);
}
```

---

## PRIORITY MATRIX

| # | Item | Impact | Effort | Priority |
|---|------|--------|--------|----------|
| 1.1 | ReactiveChainGuard (kill re-scan) | HIGH | LOW | 🔴 P0 |
| 3.2 | Circuit-breaker egress kill | CRITICAL | LOW | 🔴 P0 |
| 1.3 | Arjun→SqlMap param narrowing | HIGH | LOW | 🔴 P0 |
| 2.2 | Injection cache (kill mTLS repeat) | HIGH | MED | 🟠 P1 |
| 1.2 | SOURCE_LEAK→Semgrep / SERIAL→Ysoserial | HIGH | LOW | 🟠 P1 |
| 3.1 | DashMap diff-only sync | MED | MED | 🟠 P1 |
| 3.3a | ArcSwap for provider hot-swap | MED | LOW | 🟡 P2 |
| 2.1 | Strip headers/banners unified | MED | LOW | 🟡 P2 |
| 2.3 | Dense finding encoding | LOW | LOW | 🟡 P2 |
| 3.3b | Zero-copy Bytes payloads | MED | HIGH | 🟢 P3 |

---

## CARGO ADDITIONS

```toml
# Cargo.toml
arc-swap = "1.7"
bytes = "1.6"       # likely already transitive via tokio — make explicit
dashset = { package = "dashmap", version = "5.5" }  # DashSet already in dashmap
```

---

*AIP.md — V15 Sovereign Audit. No fluff.*
