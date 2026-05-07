# Development Guidelines

## Code Quality Standards

### Rust Code Formatting
- **Edition**: Rust 2021 edition exclusively
- **Linting**: Clippy warnings enabled at crate level (`#![warn(clippy::all)]`)
- **Async-First**: All I/O operations use async/await with Tokio runtime
- **Error Handling**: Prefer `anyhow::Result` for application errors, `thiserror` for library errors
- **Imports**: Group imports logically (std → external crates → internal modules)

### Structural Conventions
- **Module Organization**: Clear separation between core/, infrastructure/, models/, plugins/, utils/
- **Trait-Based Design**: Use `#[async_trait]` for async trait methods
- **Type Safety**: Leverage strong typing with custom types (TargetHost, Finding, etc.)
- **Visibility**: Default to private, expose only necessary public APIs

### Naming Standards
- **Variables**: snake_case for all variables and functions
- **Types**: PascalCase for structs, enums, and traits
- **Constants**: SCREAMING_SNAKE_CASE for constants
- **Modules**: snake_case for module names
- **Descriptive Names**: Use full descriptive names (proxy_manager, not pm; target_host, not th)

### Documentation
- **Module-Level Docs**: Document purpose and key components at module level
- **Function Docs**: Document public APIs with examples where appropriate
- **Inline Comments**: Use sparingly, prefer self-documenting code
- **Version Tags**: Mark significant changes with version tags (V13, V14, V15)

## Semantic Patterns

### Async Concurrency Patterns
```rust
// Pattern: Concurrent task execution with bounded parallelism
use futures::stream::{StreamExt, FuturesUnordered};

let tasks: FuturesUnordered<_> = targets
    .map(|target| async move { process_target(target).await })
    .collect();

tasks.buffer_unordered(concurrency).collect::<Vec<_>>().await;
```

### Error Handling Pattern
```rust
// Pattern: Context-aware error propagation
use anyhow::{Context, Result};

async fn operation() -> Result<()> {
    some_fallible_operation()
        .await
        .context("Failed to perform operation")?;
    Ok(())
}
```

### Proxy Management Pattern
```rust
// Pattern: Fail-closed proxy acquisition
let (proxy_url, client) = proxy_manager
    .get_client_fail_closed(&host)
    .context("OPSEC Violation: No proxy available")?;
```

### Lock-Free Concurrency
```rust
// Pattern: Use DashMap for concurrent access without explicit locking
use dashmap::DashMap;

let cache: Arc<DashMap<String, Value>> = Arc::new(DashMap::new());
cache.insert(key, value);
let result = cache.get(&key);
```

### Caching with Moka
```rust
// Pattern: TTL-based caching for expensive operations
use moka::sync::Cache;

let cache = Cache::builder()
    .max_capacity(1000)
    .time_to_idle(Duration::from_secs(3600))
    .build();

if let Some(cached) = cache.get(&key) {
    return cached;
}
let result = expensive_operation().await?;
cache.insert(key, result.clone());
```

### Sink Pattern for Data Output
```rust
// Pattern: Trait-based sink abstraction for flexible output
#[async_trait]
pub trait DataSink: Send + Sync {
    async fn write(&mut self, target: &TargetHost) -> Result<()>;
    async fn write_metadata(&mut self, metadata: &ScanMetadata) -> Result<()>;
    async fn close(&mut self) -> Result<()>;
}

// Multi-sink composition
let mut multi_sink = MultiSink::new();
multi_sink.add(Box::new(JsonlSink::new(path).await?));
multi_sink.add(Box::new(PostgresSink::new(db_url).await?));
```

### Stream Processing
```rust
// Pattern: Async stream transformation and filtering
use futures::stream::{StreamExt, BoxStream};

let stream: BoxStream<'static, TargetHost> = source_stream
    .filter(|t| async move { validate_target(&t.host) })
    .map(|t| transform_target(t))
    .boxed();
```

### Graceful Shutdown
```rust
// Pattern: Cancellation token for coordinated shutdown
use tokio_util::sync::CancellationToken;

let shutdown_token = CancellationToken::new();
let token_clone = shutdown_token.clone();

tokio::spawn(async move {
    tokio::signal::ctrl_c().await.ok();
    token_clone.cancel();
});

tokio::select! {
    _ = shutdown_token.cancelled() => {
        // Cleanup logic
    }
    result = main_task => {
        // Normal completion
    }
}
```

### Proxy Wrapping for External Tools
```rust
// Pattern: Inject proxy configuration into external commands
let mut args = vec!["--target", target];
proxy_manager.wrap_command("nmap", &mut args)?;
// args now includes proxy configuration
```

### Database Persistence Pattern
```rust
// Pattern: Async database operations with sqlx
let pool = sqlx::PgPool::connect(&db_url).await?;

let row: (i32,) = sqlx::query_as(
    "INSERT INTO targets (host, ip) VALUES ($1, $2) RETURNING id"
)
.bind(&host)
.bind(&ip)
.fetch_one(&pool)
.await?;
```

### Health Checking Pattern
```rust
// Pattern: Background health checker with abort handle
let handle = tokio::spawn(async move {
    loop {
        tokio::time::sleep(Duration::from_secs(30)).await;
        perform_health_check().await;
    }
});
self.health_checker_handle = Some(handle.abort_handle());

// Cleanup in Drop
impl Drop for Manager {
    fn drop(&mut self) {
        if let Some(handle) = self.health_checker_handle.take() {
            handle.abort();
        }
    }
}
```

## Architectural Approaches

### Tiered AI Routing
- Tier 0 (Ollama/Phi): High-volume noise filtering and basic analysis
- Tier 1/2 (Claude/GPT-4/Kimi): Complex tactical decisions and exploit planning
- Use Moka cache to deduplicate prompts and reduce API costs
- Token budgeting to prevent runaway costs

### Fail-Closed Security
- Never allow direct connections when stealth mode is active
- All external requests must go through proxy_manager
- Use `get_client_fail_closed()` to enforce proxy requirement
- DNS-rebinding protection via `is_safe_ip()` checks

### Plugin Isolation
- Execute third-party tools in Docker containers
- Use `tokio::process::Command` with `kill_on_drop(true)`
- Capture stdout/stderr for parsing
- Timeout enforcement for all plugin executions

### Lock-Free Data Structures
- Prefer DashMap over Mutex<HashMap> for concurrent access
- Use Arc for shared ownership without locks
- Moka cache for TTL-based expiration
- Atomic operations where possible

### Async Stream Composition
- Use `futures::stream::select` to merge multiple streams
- `BoxStream` for type erasure and flexibility
- `buffer_unordered` for concurrent processing with backpressure
- `filter_map` for transformation and filtering in one pass

### Modular Sink Architecture
- Implement DataSink trait for all output destinations
- MultiSink for broadcasting to multiple outputs
- Specialized sinks: JsonlSink, PostgresSink, TacticalWebhookSink, BountySink
- Async flush patterns for batching

## Common Code Idioms

### Mutex Poisoning Recovery
```rust
fn lock_proxies(&self) -> std::sync::MutexGuard<'_, Vec<String>> {
    match self.proxies.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            warn!("Mutex poisoned, recovering");
            poisoned.into_inner()
        }
    }
}
```

### Environment Variable with Fallback
```rust
let ollama_url = std::env::var("OLLAMA_URL")
    .unwrap_or_else(|_| "http://localhost:11434".to_string());
```

### Conditional Compilation Features
```rust
#[cfg(feature = "sovereign")]
fn advanced_feature() {
    // Only compiled when sovereign feature is enabled
}
```

### Structured Logging
```rust
use tracing::{info, warn, error};

info!("🚀 Starting operation for target: {}", target);
warn!("⚠️ Proxy pool exhausted, waiting...");
error!("❌ Failed to connect: {}", e);
```

### JSON Serialization with Context
```rust
let json = serde_json::to_string(&data)
    .context("Failed to serialize data")?;
```

### Path Traversal Protection
```rust
let path = std::path::Path::new(user_input);
if path.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
    anyhow::bail!("Path traversal detected");
}
```

### HTML Escaping for Reports
```rust
use html_escape::encode_safe;

let safe_host = encode_safe(&target.host).to_string();
```

### Compression for Network Efficiency
```rust
use flate2::write::GzEncoder;
use flate2::Compression;

let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
encoder.write_all(&json)?;
let compressed = encoder.finish()?;
```

## Testing Practices

### Unit Tests
- Place tests in `#[cfg(test)]` modules at bottom of files
- Use `#[tokio::test]` for async tests
- Test both success and error paths
- Mock external dependencies where possible

### Integration Tests
- Separate integration tests in `tests/` directory
- Test end-to-end workflows
- Use test fixtures for reproducibility

## Security Practices

### Input Validation
- Validate all user inputs before processing
- Use `validate_target()` for target validation
- Check for path traversal in file operations
- Sanitize data before database insertion

### Credential Management
- Never hardcode credentials
- Load from environment variables via `.env` files
- Use secure file permissions (0o600) for sensitive files
- Mask credentials in logs

### SSRF Protection
```rust
use crate::utils::security::is_ssrf_safe_host_async;

if !is_ssrf_safe_host_async(&host).await {
    anyhow::bail!("SSRF protection: Host is not safe");
}
```

### Rate Limiting
- Use adaptive delays based on proxy latency
- Implement jitter for human-like behavior
- Respect rate limits from external APIs

## Performance Optimization

### Memory Management
- Use streaming for large files (avoid loading entire file in memory)
- Implement bounded channels to prevent unbounded growth
- Monitor memory usage with sysinfo crate
- Set capacity hints for collections when size is known

### Database Optimization
- Use connection pooling (sqlx::PgPool)
- Batch inserts where possible
- Use ON CONFLICT for upserts
- Index frequently queried columns

### Caching Strategy
- Cache expensive operations (AI inference, CVE lookups)
- Use TTL to prevent stale data
- Implement cache warming for predictable access patterns
- Monitor cache hit rates

## Version Control Practices

### Commit Messages
- Use conventional commit format
- Reference issue numbers where applicable
- Include version tags for major changes (V13, V14, V15)

### Code Review
- All changes require review before merge
- Run `cargo clippy` and `cargo test` before submitting
- Document breaking changes clearly
- Update relevant documentation

## Deployment Considerations

### Configuration Management
- Use `.env.oracle` for production configuration
- Validate all required environment variables at startup
- Provide sensible defaults where appropriate
- Document all configuration options

### Logging and Monitoring
- Use structured logging with tracing
- Configure log levels via environment variables
- Integrate OpenTelemetry for distributed tracing
- Monitor resource usage (CPU, memory, network)

### Error Recovery
- Implement graceful degradation
- Retry transient failures with exponential backoff
- Log errors with sufficient context for debugging
- Provide clear error messages to users
