# OsintUltimate - Development Guidelines

## Code Quality Standards Analysis

### 1. Error Handling Patterns (5/5 files)
- **Primary Pattern**: `anyhow::Result<T>` for application-level errors
- **Custom Errors**: `thiserror` crate for library/API boundaries
- **Context Wrapping**: `.context("descriptive message")` for error chains
- **Early Returns**: `anyhow::bail!("message")` for early error exits
- **Result Propagation**: `?` operator with proper error conversion

```rust
// Example from main.rs
use anyhow::{Context, Result};
async fn main() -> Result<()> {
    redteam_rust_core::utils::init_telemetry(args.otel_endpoint.clone(), args.json_logs, None)
        .context("Failed to initialize telemetry")?;
    // ...
}
```

### 2. Async/Await Patterns (5/5 files)
- **Runtime**: `#[tokio::main]` with async main function
- **Stream Processing**: `futures::stream` combinators for data pipelines
- **Concurrency**: `buffer_unordered(concurrency)` for parallel processing
- **Channel Communication**: `tokio::sync::mpsc` and `broadcast` channels
- **Task Spawning**: `tokio::spawn` for background operations

```rust
// Example from orchestrator.rs
let mut join_set = tokio::task::JoinSet::new();
for i in 0..plugins.len() {
    let p = &plugins[i];
    join_set.spawn(async move {
        // Async plugin execution
    });
}
```

### 3. Logging Patterns (5/5 files)
- **Structured Logging**: `tracing` crate with `info!`, `warn!`, `error!`, `debug!`
- **Log Levels**: Info for operations, Warn for issues, Error for failures
- **Contextual Logging**: Include relevant identifiers (host, plugin, session_id)
- **Emoji Prefixes**: Visual indicators for log categories (🚀, 🛡️, ⚠️, ❌)
- **JSON Logs**: Optional JSON format for structured processing

```rust
// Example from main.rs
info!("🚀 Mimikri Core v0.1.0 starting...");
warn!("🛡️ [PREFLIGHT] P0 TOOL MISSING: {}. Pipeline may be incomplete.", tool);
error!("❌ [MCP-RESILIENCIA] Plugin {} falló definitivamente", plugin_name);
```

### 4. Configuration Patterns (4/5 files)
- **Environment Variables**: `dotenv::dotenv().ok()` for .env loading
- **CLI Arguments**: `clap` with derive macros for command-line interface
- **Feature Flags**: Cargo features for conditional compilation
- **Config Structs**: Immutable configuration passed to components
- **Validation**: Early validation of configuration values

```rust
// Example from main.rs
#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    pub target: Option<String>,
    #[arg(long, help = "Path to local APK/IPA for mobile scanning")]
    pub apk: Option<String>,
    // ... many other options
}
```

## Structural Conventions

### 1. Module Organization (5/5 files)
- **Core Modules**: `core/` for main engine components
- **Plugin System**: `plugins/` for scanner implementations
- **Models**: `models/` for data structures and enums
- **Utilities**: `utils/` for helper functions
- **Infrastructure**: `infrastructure/` for external integrations

### 2. State Management (4/5 files)
- **Arc Sharing**: `Arc<T>` for shared immutable state
- **DashMap**: `dashmap::DashMap` for concurrent hash maps
- **Atomic Counters**: `AtomicU32`, `AtomicU64` for metrics
- **Mutex/RwLock**: `tokio::sync::Mutex` for mutable shared state
- **Channel-based**: Message passing for component communication

```rust
// Example from mcp/server.rs
pub struct McpServer {
    pub(crate) config: Arc<GlobalConfig>,
    pub(crate) sanitizer: Arc<DataSanitizer>,
    pub(crate) sessions: Arc<dashmap::DashMap<String, mpsc::Sender<Event>>>,
    pub(crate) db: Option<Arc<PostgresSink>>,
    pub(crate) plugin_cache: Cache<String, String>,
    // Atomic metrics
    pub total_calls: AtomicU32,
    pub cache_hits: AtomicU32,
    pub tokens_saved: AtomicU64,
    pub bytes_processed: AtomicU64,
}
```

### 3. Plugin Architecture (3/5 files)
- **Trait-based**: `ScannerPlugin` trait with `scan()` method
- **Metadata**: Plugin metadata for capability discovery
- **Dependency Checking**: `check_dependencies()` method
- **Capability Enum**: `Capability` enum for plugin classification
- **Registry Pattern**: Central plugin registry for discovery

## Textual Standards

### 1. Naming Conventions (5/5 files)
- **Snake Case**: `run_autopilot`, `init_stealth_infrastructure`
- **Pascal Case**: `TargetHost`, `ScanLayer`, `OptimizationLevel`
- **Constants**: `UPPER_SNAKE_CASE` for constants
- **Acronyms**: Preserve case in acronyms (`MCP`, `SSE`, `JSON`)
- **Spanish Terms**: Mixed Spanish/English for internal documentation

### 2. Documentation Patterns (4/5 files)
- **Module Docs**: `//!` for module-level documentation
- **Function Docs**: `///` with parameter descriptions
- **Example Code**: Code examples in documentation
- **Safety Notes**: `# Safety` sections for unsafe code
- **TODO/FIXME**: Comments for future improvements

### 3. Comment Style (5/5 files)
- **Section Headers**: `// --- SECTION NAME ---` for code organization
- **Inline Comments**: Brief explanations of complex logic
- **Spanish Comments**: Mixed Spanish/English comments
- **Emoji Indicators**: Visual markers in comments
- **Version Tags**: `V14.2`, `V15` for feature versioning

## Practices Followed

### 1. Security Practices (5/5 files)
- **Input Validation**: `validate_target()` for target safety
- **Path Sanitization**: `validate_path()` for file operations
- **Token Authentication**: Bearer token validation
- **CORS Restrictions**: Strict origin matching
- **Data Masking**: `DataSanitizer` for sensitive data

### 2. Performance Practices (4/5 files)
- **Caching**: `moka` cache for plugin results
- **Memory Management**: Semaphore-based memory limits
- **Stream Processing**: Lazy evaluation with streams
- **Atomic Operations**: Lock-free counters for metrics
- **Connection Pooling**: Database connection reuse

### 3. Testing Practices (2/5 files)
- **Unit Tests**: `#[cfg(test)]` modules with test functions
- **Integration Tests**: End-to-end testing patterns
- **Mocking**: Trait-based mocking for dependencies
- **Property Testing**: Example-based property tests
- **Benchmarks**: Performance benchmarking

## Semantic Patterns Overview

### 1. Recurring Implementation Patterns

**Pipeline Pattern** (3/5 files):
```rust
// Data flows through processing stages
target_stream → filter → map → process → sink
```

**Builder Pattern** (2/5 files):
```rust
// Fluent interface for object construction
Orchestrator::new(config)
    .with_swarm_mode(true, max_tokens, router, proxy_manager)
    .with_dashboard_preconfigured(tx, targets)
```

**Strategy Pattern** (1/5 files):
```rust
// Token optimization strategies
trait OptimizationStrategy {
    fn optimize(&self, input: &str, level: OptimizationLevel) -> String;
}
```

### 2. Common Architectural Approaches

**Event-Driven Architecture** (4/5 files):
- SSE (Server-Sent Events) for real-time updates
- Broadcast channels for multi-consumer patterns
- WebSocket for bidirectional communication

**Microservices Communication** (3/5 files):
- HTTP REST APIs for external communication
- NATS messaging for distributed coordination
- PostgreSQL for shared state persistence

**Plugin System** (3/5 files):
- Dynamic plugin loading and registration
- Capability-based plugin selection
- Dependency injection for plugin configuration

### 3. Frequent Design Patterns

**Factory Pattern** (2/5 files):
```rust
// Engine factory for infrastructure detection
EngineFactory::detect_infrastructure_limits()
```

**Observer Pattern** (3/5 files):
```rust
// Dashboard updates via broadcast channels
dashboard_tx.send(finding.clone())
```

**Chain of Responsibility** (2/5 files):
```rust
// Reactive trigger chains in orchestrator
SSTI finding → Commix plugin → RCE detection
```

### 4. Proper Internal API Usage

**Async Stream Processing** (4/5 files):
```rust
// Proper stream composition
let target_stream = futures::stream::select(target_hosts, injection_stream).boxed();
```

**Error Propagation** (5/5 files):
```rust
// Consistent error handling
match engine.run_autopilot(target_stream, sink).await {
    Ok(_) => info!("✅ Completed"),
    Err(e) => error!("❌ Failed: {}", e),
}
```

**Resource Management** (3/5 files):
```rust
// RAII pattern for resource cleanup
let _permit = memory_semaphore_clone.acquire_many(permits_needed).await;
```

### 5. Frequently Used Code Idioms

**Early Returns** (5/5 files):
```rust
if !validate_target(&target) {
    anyhow::bail!("Invalid target provided: {}", target);
}
```

**Pattern Matching** (4/5 files):
```rust
match target_type {
    TargetType::Web => { /* web scanning */ }
    TargetType::Network => { /* network scanning */ }
    TargetType::Mobile => { /* mobile scanning */ }
    _ => { /* default handling */ }
}
```

**Option/Result Combinators** (4/5 files):
```rust
args.proxies.as_ref()
    .map(|s| s.split(',').map(|p| p.trim().to_string()).collect())
    .unwrap_or_default()
```

### 6. Popular Annotations and Attributes

**Compiler Directives** (3/5 files):
```rust
#![warn(clippy::all)]  // Enable all clippy warnings
#[derive(Debug, Clone)] // Common derives
#[cfg(feature = "sovereign")] // Feature-gated code
```

**Async Attributes** (4/5 files):
```rust
#[tokio::main]
async fn main() -> Result<()> {
    // Async entry point
}

#[async_trait]
impl FromRequestParts<Arc<McpServer>> for ValidatedOperator {
    // Async trait implementation
}
```

**Serialization Attributes** (3/5 files):
```rust
#[derive(serde::Serialize, serde::Deserialize)]
struct Finding {
    // JSON serializable struct
}
```

## Development Workflow Guidelines

### 1. Code Organization
- Keep related functionality in the same module
- Use submodules for complex components
- Follow the existing directory structure
- Document public APIs thoroughly

### 2. Error Handling
- Use `anyhow::Result` for application code
- Use `thiserror` for library boundaries
- Provide context for errors
- Handle errors at appropriate boundaries

### 3. Async Programming
- Use `tokio` runtime features appropriately
- Avoid blocking calls in async functions
- Use proper synchronization primitives
- Handle cancellation gracefully

### 4. Testing
- Write unit tests for core logic
- Test error conditions
- Mock external dependencies
- Include integration tests for critical paths

### 5. Performance
- Use appropriate data structures
- Implement caching where beneficial
- Monitor memory usage
- Profile performance-critical code

### 6. Security
- Validate all external inputs
- Sanitize file paths
- Use proper authentication
- Follow principle of least privilege