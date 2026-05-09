# AIP — Architect Improvement Plan

> Source-verified audit. Status column updated against actual `src/`. Last verified: 2026-05-08.
> Format: **PROBLEM → FIX → IMPACT → STATUS**

---

## STATUS LEGEND

| Symbol | Meaning |
|---|---|
| ✅ | Implemented and verified in source |
| 🔴 | Pending — P0 (critical, blocking) |
| 🟠 | Pending — P1 (high, next sprint) |
| 🟡 | Pending — P2 (medium, backlog) |
| 🟢 | Pending — P3 (nice-to-have) |

---

## [1] FLOW: PIPELINE-CRUSH

### 1.1 🔴 ReactiveChainGuard — Kill Re-Scan (P0)

**Problem:** `orchestrator.rs` reactive triggers re-scan the same `target` snapshot after the main plugin `JoinSet` completes. No deduplication guard — a finding triggering multiple reactive chains causes redundant tool invocations (SSTI→Commix, SBOM→Grype, GQL→Schemathesis, JS→Retire, Mobile, Cloud, AI all fire independently against the same finding).

**Fix:**

```rust
// models/findings.rs — reactive-chain dedup marker
#[derive(Default)]
pub struct ReactiveChainGuard(DashSet<String>);

impl ReactiveChainGuard {
    /// Returns true only on first fire for (finding_id, plugin_name) pair.
    pub fn fire(&self, finding_id: &str, plugin: &str) -> bool {
        self.0.insert(format!("{}:{}", finding_id, plugin))
    }
}

// orchestrator.rs — thread guard through ALL reactive triggers
let chain_guard = ReactiveChainGuard::default();
if chain_guard.fire(FINDING_SSTI, PLUGIN_COMMIX) { /* commix scan */ }
if chain_guard.fire(FINDING_SBOM_INVENTORY, PLUGIN_GRYPE) { /* grype scan */ }
```

**Impact:** Eliminates duplicate reactive scans. Zero re-scan on same `finding_id + plugin` pair per target.

---

### 1.2 🟠 Missing Reactive Triggers (P1)

**Problem:** `orchestrator.rs` has reactive triggers for SSTI, SBOM, GraphQL, JS, Mobile, Cloud, AI — but **no trigger for**:
- `SOURCE-CODE-EXPOSED | GIT-REPO-EXPOSED | BACKUP-FILE` → `SemgrepScanner` (`plugins/compliance/semgrep.rs`)
- `JAVA-SERIAL | PICKLE | YSOSERIAL` → `DeserializationScanner` (`plugins/exploitation/web/deserialization.rs`)

Both plugins exist in source but are not wired as reactive triggers.

**Fix:**

```rust
// orchestrator.rs — add after main JoinSet collection
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
// Same pattern for deserialization scanner on JAVA-SERIAL/PICKLE/YSOSERIAL
```

**Impact:** Closes two high-value reactive chain gaps. Source code exposure now auto-triggers static analysis.

---

### 1.3 🔴 Arjun→SqlMap Param Narrowing (P0)

**Problem:** `SqlMapScanner` runs against the full target URL. `ArjunScanner` discovers parameters and produces `ARJUN-PARAMS-FOUND` findings, but this output is **never fed into SqlMap's parameter list**. SqlMap defaults to full crawl + bruteforce.

**Fix:**

```rust
// orchestrator.rs — after JoinSet collection, before reactive triggers
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
        .map(|obj| obj.insert("sqlmap_params".into(), serde_json::json!(arjun_params.join(","))));
}

// plugins/exploitation/web/sqlmap.rs — consume narrowed params
let params = target.extra_data.get("sqlmap_params").and_then(|v| v.as_str());
if let Some(p) = params {
    cmd.args(["--data", p, "--level=1", "--risk=1"]); // no bruteforce
} else {
    cmd.args(["--forms", "--level=1", "--risk=1"]);
}
```

**Impact:** SqlMap runs targeted, not blind. ~60% scan time reduction on parameterized targets. Eliminates bruteforce parameter discovery.

---

## [2] TOKENS: DATA-GUT

### 2.1 🟡 Unified Header Strip — Raw Vuln Vector Only (P2)

**Problem:** `compressor.rs::compress_finding()` retains 7 headers (`server`, `x-powered-by`, `csp`, `x-frame-options`, `sts`, `location`, `www-authenticate`). Only `server` and `x-powered-by` carry tactical AI signal. The unified path should strip to minimal set.

**Fix:**

```rust
// compressor.rs — replace whitelist in minify_evidence_object()
fn minify_evidence_object(obj: &mut serde_json::Map<String, Value>, body_limit: usize) {
    // truncate body
    if let Some(val) = obj.get_mut("body") {
        if let Some(s) = val.as_str() {
            if s.len() > body_limit {
                *val = serde_json::json!(format!("{}...[T]", &s[..body_limit]));
            }
        }
    }
    // UNIFIED: only tactical headers, always
    Self::minify_headers(obj, &["server", "x-powered-by"]);
    obj.remove("banner");
    obj.remove("raw_response");
}
```

**Impact:** ~15-25% token reduction per finding on header-heavy HTTP findings.

---

### 2.2 ✅ Injection Cache — Kill mTLS Fingerprint Repeat

**Status: IMPLEMENTED** in `src/core/ai/router.rs`.

`injection_cache: Cache<String, String>` with 1000 entries, 30-min TTL. Key format: `"inj:{level:?}:{posture:?}:{caveman:?}:{finding_id}"`. Verified in `enrich_context_v15()`.

**Remaining gap:** `ContextCompressor::compress_target()` still iterates all findings O(n) per call to extract tech stack. `compress_target_lean()` for Tier 0 calls not yet added.

```rust
// compressor.rs — add lean variant for Tier 0
pub fn compress_target_lean(target: &TargetHost) -> serde_json::Value {
    serde_json::json!({
        "h":    target.host,
        "ip":   target.ip.as_deref().unwrap_or("?"),
        "type": format!("{:?}", target.target_type),
    })
}
```

---

### 2.3 🟡 Dense Finding Encoding (P2)

**Problem:** `compress_finding()` emits `"conf": "POTENTIAL"/"VERIFIED"`, `"sev": "Critical"` as full strings. Low-entropy tokens for LLM consumption.

**Fix:**

```rust
// compressor.rs
pub fn compress_finding_dense(finding: &Finding) -> serde_json::Value {
    let sev_code = match finding.core.severity {
        Severity::Critical => "C", Severity::High => "H",
        Severity::Medium   => "M", Severity::Low  => "L", Severity::Info => "I",
    };
    let verified = finding.evidence.evidence.as_ref()
        .map(|e| if e.verified { 1 } else { 0 }).unwrap_or(0);
    serde_json::json!({
        "id":   finding.core.id,
        "s":    sev_code,
        "v":    verified,
        "cvss": finding.enrichment.cvss_score,
        "d":    finding.core.description.chars().take(150).collect::<String>(),
    })
}
```

**Impact:** ~20% token reduction per finding. Significant at 50 findings × 50 targets scale.

---

## [3] CORE: HARDEN-EGRESS

### 3.1 🟠 DashMap Diff-Only Sync (P1)

**Status: PARTIAL.** `TargetHost.version` field exists in `models/scan_result.rs` (seen in target construction: `version: 0`). Dashboard insert uses it. However, the web handler `get_targets()` diff filter on `?since=<version>` is **not verified in `src/core/web/handlers.rs`** — needs audit.

**Remaining work:** Verify `handlers.rs::get_targets()` implements the `since` filter. If not:

```rust
pub async fn get_targets(
    Query(params): Query<HashMap<String, u64>>,
    State(state): State<Arc<DashboardState>>,
) -> Json<Vec<serde_json::Value>> {
    let since = params.get("since").copied().unwrap_or(0);
    let targets: Vec<_> = state.targets.iter()
        .filter(|kv| kv.value().version > since)
        .map(|kv| serde_json::to_value(kv.value().clone()).unwrap_or_default())
        .collect();
    Json(targets)
}
```

**Impact:** Dashboard poll goes from O(n_targets) full serialize to O(changed_targets) diff. Critical for long-running scans.

---

### 3.2 ✅ Circuit-Breaker: Global Egress Kill Switch

**Status: IMPLEMENTED.** `ProxyManager::kill_egress()` is present and called in the Ctrl-C handler in `main.rs`:

```rust
// main.rs kill-switch handler:
pm_clean.kill_egress();
shutdown_signal.cancel();
do_client.destroy_all_ephemeral_droplets().await?;
```

**Remaining gap:** `StealthExecutor::execute()` does not check `egress_killed` flag before spawning commands. A tool could still run between `kill_egress()` call and `CancellationToken` propagation.

**Fix — add pre-flight check in executor:**

```rust
// utils/executor.rs — before every command spawn
if self.proxy_manager.as_ref()
    .map(|pm| pm.is_egress_killed())
    .unwrap_or(false)
{
    anyhow::bail!("OPSEC: Egress killed. Command '{}' blocked.", binary);
}
```

---

### 3.3a ✅ ArcSwap for Provider Hot-Swap

**Status: IMPLEMENTED.** `src/core/ai/router.rs`:

```rust
pub struct TieredAIRouter {
    pub providers: ArcSwap<HashMap<RouteLevel, Vec<ProviderEntry>>>,
    // ...
}
```

`rcu()` used for lock-free atomic updates. Verified in `add_provider()`.

---

### 3.3b 🟢 Zero-Copy Bytes Payloads (P3)

**Problem:** `sandbox.rs` and `executor.rs` pass tool output as `String`. For large Nmap XML or Nuclei outputs, this is an unnecessary heap allocation + copy.

**Fix:**

```rust
use bytes::Bytes;

pub struct ToolOutput {
    pub stdout: Bytes,
    pub stderr: Bytes,
    pub exit_code: i32,
}

// Plugin parsers accept &[u8] — no String allocation needed
pub fn parse_nmap_output(raw: &[u8]) -> Result<Vec<Finding>> { ... }
```

**Impact:** Reduces peak memory on large-output tools. Useful at 150-concurrency server deployments.

---

## PRIORITY MATRIX (Updated)

| # | Item | Status | Impact | Priority |
|---|------|--------|--------|----------|
| 1.1 | ReactiveChainGuard — kill re-scan | 🔴 Pending | HIGH | P0 |
| 1.3 | Arjun→SqlMap param narrowing | 🔴 Pending | HIGH | P0 |
| 1.2 | SOURCE_LEAK→Semgrep / SERIAL→Ysoserial | 🟠 Pending | HIGH | P1 |
| 3.1 | DashMap diff-only sync (verify handler) | 🟠 Partial | MED | P1 |
| 3.2 | Executor egress-killed pre-flight | 🟠 Partial | CRITICAL | P1 |
| 2.2 | compress_target_lean for Tier 0 | 🟠 Partial | MED | P1 |
| 3.3a | ArcSwap providers | ✅ Done | MED | — |
| 2.2 | Injection cache | ✅ Done | HIGH | — |
| 3.2 | kill_egress() kill-switch | ✅ Done | CRITICAL | — |
| 2.1 | Unified header strip | 🟡 Pending | MED | P2 |
| 2.3 | Dense finding encoding | 🟡 Pending | LOW | P2 |
| 3.3b | Zero-copy Bytes payloads | 🟢 Pending | MED | P3 |

---

## Cargo Dependencies

All already present in `Cargo.toml`. No new additions needed for remaining items:

```toml
arc-swap = "1.7"        # ✅ already used
moka = { ..., features = ["future"] }  # ✅ already used for caches
dashmap = "5.5"         # ✅ DashSet available
```
