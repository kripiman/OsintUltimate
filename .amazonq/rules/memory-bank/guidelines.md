# OsintUltimate — Development Guidelines

## Code Quality Standards

### Error Handling
- Use `anyhow::Result` for fallible public functions; `thiserror` for typed domain errors
- Prefer `context()`/`with_context()` over bare `?` to add call-site information
- Return `Ok(Vec::new())` from plugins when nothing found; only `Err` on fatal execution failure
- Use `anyhow::bail!()` for early-exit validation failures

```rust
// Correct pattern
let path = std::fs::canonicalize(path)
    .with_context(|| format!("Failed to canonicalize path: {:?}", path))?;

// Plugin scan: no findings ≠ error
async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
    if !self.check_dependencies().await? { return Ok(vec![]); }
    // ...
}
```

### Async Patterns
- All I/O must be async (`tokio::fs`, `tokio::process::Command`, `reqwest`)
- Never use `std::thread::sleep` — always `tokio::time::sleep`
- Use `tokio::task::spawn_blocking` for CPU-bound or FFI calls
- Wrap FFI calls with `tokio::time::timeout` + `catch_unwind(AssertUnwindSafe(...))`
- Use `JoinSet` for parallel plugin execution with panic isolation

```rust
// FFI panic isolation pattern
let result = tokio::time::timeout(timeout_duration, tokio::task::spawn_blocking(move || {
    catch_unwind(AssertUnwindSafe(move || { (ffi.scan)(ptr, &target_ffi) }))
})).await;
```

### Concurrency & Shared State
- Use `Arc<DashMap<K, V>>` for concurrent shared maps (never `Mutex<HashMap>` in hot paths)
- Use `Arc<std::sync::atomic::AtomicU64>` for counters (not `Mutex<u64>`)
- `crossbeam::queue::ArrayQueue` for bounded lock-free queues
- `moka::future::Cache` for async TTL caches with capacity limits
- `once_cell::sync::Lazy` for static initialization of regexes and global singletons

```rust
// Static regex — compiled once, never in hot path
static RE_ARTICLES: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\b(the|a|an)\b").unwrap());

// Atomic counter pattern
pub total_calls: AtomicU32,
self.total_calls.fetch_add(1, Ordering::Relaxed);
```

### Security-First Patterns
- **Path validation**: Always `canonicalize()` + `starts_with(workspace_root)` before file access
- **Fail-closed networking**: Use `proxy_manager.get_client_fail_closed(host)?` — never fall back to direct connections
- **Secret scrubbing**: Pass all data through `SCRUBBER.scrub()` before sending to remote LLMs
- **Command injection prevention**: Validate all args against forbidden prefixes and shell metacharacters before execution
- **DNS pinning**: Use `target.pinned_addr()?` (returns `Err` if not resolved) for all network ops

```rust
// Fail-closed client — aborts if no proxy
let (_, client) = self.proxy_manager.get_client_fail_closed(api_host)
    .context("OPSEC: No proxy available")?;

// Path traversal prevention
if !target_path.starts_with(&workspace_root) {
    return Err("PATH VIOLATION: outside workspace".into());
}
```

## Structural Conventions

### Plugin Implementation
Every scanner plugin must implement `ScannerPlugin` trait:
```rust
#[async_trait]
impl ScannerPlugin for MyScanner {
    fn name(&self) -> &'static str { "MyScanner" }
    fn metadata(&self) -> PluginMetadata { /* layer, risk_level, capabilities */ }
    fn capabilities(&self) -> Vec<Capability> { vec![Capability::VulnerabilityScanning] }
    async fn check_dependencies(&self) -> Result<bool> { Ok(check_tool_availability("tool").await) }
    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> { /* ... */ }
}
```

### Finding Construction
Always use `Finding::new()` constructor; chain builder methods for optional fields:
```rust
let finding = Finding::new("FINDING-ID", Category::Vulnerability, Severity::High, "description", 
    serde_json::json!({"key": "value"}))
    .with_cvss_vector("CVSS:4.0/...")
    .with_mitre_attack(vec!["T1190".to_string()])
    .with_execution_context("OBJ-001", "Scout", 1);
```

### Named Constructor Pattern
Provide semantic constructors for configuration types:
```rust
impl ApprovalGate {
    pub fn for_red_team() -> Self { Self::new(80) }
    pub fn for_authorized_testing() -> Self { Self::new(100) }
    pub fn for_compliance() -> Self { Self::new(50) }
}
```

### Builder Pattern
Complex structs use builder pattern with method chaining:
```rust
let pipeline = Pipeline::builder()
    .concurrency(10)
    .with_sink(sink)
    .layer_policy(policy)
    .sandbox(sandbox)
    .build()?;
```

### FFI Safety
- All FFI structs must be `#[repr(C)]`
- ABI version check on load: `if version != PLUGIN_ABI_VERSION { bail!(...) }`
- Use `Box::leak()` to satisfy `&'static str` for plugin names
- Always call plugin-provided `free_data_fn` and `free_findings_struct` — never `Box::from_raw` on plugin memory
- Wrap `unsafe` blocks with explicit SAFETY comments

## Naming Conventions
- Types: `PascalCase` — `ProxyManager`, `SwarmOrchestrator`, `TieredAIRouter`
- Functions/methods: `snake_case` — `get_client_fail_closed`, `run_autopilot`
- Constants: `SCREAMING_SNAKE_CASE` — `PLUGIN_ABI_VERSION`, `FINDING_TECH_STACK`
- Modules: `snake_case` — `approval_gate`, `lock_free_sink`
- Versioning comments: `// V14.1 HARDENING:`, `// V13:`, `// ARCH-10:` prefix for change tracking

## Logging Standards
Use `tracing` macros with emoji prefixes for visual scanning:
```rust
info!("🚀 EXECUTOR: Spawning process: {} {}", binary, args);
warn!("⚠️ V13: Resolution failed for host {}.", target.host);
error!("❌ [MCP-RESILIENCIA] Plugin {} failed: {}", plugin_name, e);
info!("🛡️ [MCP-OPSEC] Interpolating '{}' -> Real: '{}'", masked, real);
```

Log levels:
- `info!` — normal operational events, cache hits, plugin execution
- `warn!` — degraded operation, blacklisted proxies, loop detection
- `error!` — plugin failures, security violations, kill-switch events

## Testing Patterns
- Unit tests in `#[cfg(test)] mod tests` at bottom of each file
- Use `#[tokio::test]` for async tests
- Use `tempfile::tempdir()` for filesystem tests
- Test both happy path and error/boundary conditions
- Assert specific error messages with `.to_string().contains(...)`

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_auto_approval_low_risk() {
        let gate = ApprovalGate::for_red_team();
        let result = gate.request_approval("action", 30, &user, "reason").await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none()); // auto-approved
    }
}
```

## Token Optimization Patterns
The codebase has a pervasive token-efficiency concern for LLM interactions:
- Use `ContextCompressor::compress_finding(f, route_level)` before sending to AI
- Apply `PROMPT_OPTIMIZER.optimize(text, OptimizationLevel::Full)` to prose output
- Use `SCRUBBER.scrub(text)` before any remote LLM call
- Prefer TONL V1.1 > TONE V1 > JSON for multi-finding output
- Track savings with `PromptOptimizer::savings_tokens(original, optimized)`

## Strategy Pattern (Optimization Pipeline)
Internal processing pipelines use the Strategy pattern with a `Vec<Box<dyn Trait>>`:
```rust
trait OptimizationStrategy: Send + Sync {
    fn optimize(&self, input: &str, level: OptimizationLevel) -> String;
}

pub struct PromptOptimizer {
    strategies: Vec<Box<dyn OptimizationStrategy>>,
}
// Stage order is significant — document it with numbered comments
```

## Versioning & Change Tracking
- Prefix significant changes with version tags in comments: `// V14.1`, `// ARCH-10`, `// AUDIT-002`
- Document safety contracts explicitly: `// SAFETY: CStrings kept alive until scan returns`
- Document OPSEC implications: `// V13 OPSEC Violation: ...`
- Use `#[non_exhaustive]` on enums that may gain variants (e.g., `PocStrategy`)
