# 🔌 Plugin Development Guide

OsintUltimate leverages a modular architecture where every scanning capability is a plugin implementing the `ScannerPlugin` trait.

## The Trait Interface

Located in `src/plugins/mod.rs`:

```rust
#[async_trait]
pub trait ScannerPlugin: Send + Sync {
    /// Unique identifier for the plugin (e.g., "WebFuzzer")
    fn name(&self) -> &'static str;

    /// Detailed metadata including risk levels and MITRE mapping
    fn metadata(&self) -> PluginMetadata;

    /// List of capabilities provided by the plugin
    fn capabilities(&self) -> Vec<Capability>;

    /// Asynchronous check for system dependencies (e.g., bin availability)
    async fn check_dependencies(&self) -> Result<bool>;

    /// The core logic. Returns a list of findings for a specific target.
    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>>;
}
```

## Creating a New Scanner

### Step 1: Define the Structure
Your struct can contain specialized configurations or shared resources like an `Arc<StealthExecutor>`.

```rust
pub struct MyCustomScanner {
    port: u16,
    executor: Arc<StealthExecutor<GhostMode>>,
}
```

### Step 2: Implement the Trait

```rust
use async_trait::async_trait;
use crate::models::{TargetHost, Finding, Severity, Category};
use crate::plugins::{ScannerPlugin, PluginMetadata, Capability};
use anyhow::Result;

#[async_trait]
impl ScannerPlugin for MyCustomScanner {
    fn name(&self) -> &'static str {
        "MyCustomScanner"
    }

    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: self.name().to_string(),
            description: "Custom network probe for specific ports.".to_string(),
            risk_level: RiskLevel::Low,
            layer: ScanLayer::Discovery,
            // ... see PluginMetadata definition for more fields
            ..Default::default()
        }
    }

    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        // 1. Perform logic (e.g., via StealthExecutor)
        let output = self.executor.execute_and_wait("probe", vec![target.host.clone()]).await?;
        
        // 2. Parse findings
        if output.status.success() {
             findings.push(Finding::new(
                "CUSTOM-VULN-01",
                Category::Network,
                Severity::High,
                "Target is vulnerable to custom probe.",
                serde_json::json!({ "output": String::from_utf8_lossy(&output.stdout) })
            ));
        }
        
        Ok(findings)
    }
}
```

### Step 3: Registration
Register the plugin in `src/plugins/mod.rs` within the `get_all_scanners` function.

---

## Best Practices

1.  **Non-Blocking**: Never use `std::thread::sleep`. Always use `tokio::time::sleep` and async I/O.
2.  **Sovereign Egress**: Any external binary execution MUST go through the `StealthExecutor::spawn` or `execute_and_wait` methods to ensure proxy wrapping.
3.  **Error Handling**: Return `Ok(vec![])` if no vulnerabilities are found. Only return `Err` if the plugin itself experienced a fatal execution error.

## Dynamic Plugins (.so / .dylib)

OsintUltimate supports loading plugins as independent dynamic libraries. The core verifies **ABI compatibility** and **Version matching** before loading. Use the `--plugins-dir <path>` flag to load them.

---

## 🎯 BlackArch Integration

As of V14.1, OsintUltimate automatically detects BlackArch tools installed on the system using the `utils::tool_detection` module. This ensures that the engine uses optimized system binaries instead of embedded fallbacks.

### Currently Supported Tools (Partial List)
| Tool | Plugin | Category |
| :--- | :--- | :--- |
| **ffuf** | FfufScanner | Web Enumeration |
| **nuclei** | NucleiScanner | Vulnerability Intelligence |
| **sqlmap** | SqlMapScanner | Exploitation |
| **bloodhound** | BloodHoundScanner | Lateral Movement |
| **sliver** | SliverScanner | C2 Operations |

---

## 🚀 Native Scanners (io-uring)

For network tasks requiring ultra-low latency (like massive port scanning), OsintUltimate utilizes the `NativeScanner` trait, which bypasses the traditional process model in favor of `io-uring`.

### Advantages:
1. **Zero-Copy**: Direct packet transmission from kernel-shared buffers.
2. **Lock-Free**: Ingestion of results directly into the `LockFreeResultSink`.
3. **Scale**: Capable of handling >100k pps (packets per second).

---

© 2026 RedTeam Lab | OsintUltimate V14.1 Developer Manual
