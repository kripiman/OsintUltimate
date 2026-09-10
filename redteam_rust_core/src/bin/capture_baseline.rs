use redteam_rust_core::models::{TargetHost, TargetStatus, TargetType};
use redteam_rust_core::plugins::get_all_scanners;
use redteam_rust_core::core::orchestrator::dispatch::dispatch_scan;
use redteam_rust_core::core::capability_layer::ScanLayerPolicy;
use redteam_rust_core::core::approval_gate::ApprovalGate;
use redteam_rust_core::utils::memory_monitor::MemoryMonitor;
use redteam_rust_core::plugins::GlobalConfig;
use redteam_rust_core::utils::executor::GhostMode;
use std::sync::Arc;
use std::fs;
use anyhow::Result;
use tokio::sync::Semaphore;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    println!("🚀 Starting REAL Golden Scan Baseline Capture (V15 Architecture)...");
    
    // 1. Setup Environment Dependencies (Explicit GhostMode for baseline)
    let config = GlobalConfig::<GhostMode>::new();
    let plugins = Arc::new(get_all_scanners(config.clone()));
    
    // Using established presets from V15 core
    let layer_policy = ScanLayerPolicy::preset_authorized_red_team(); 
    let approval_gate = Arc::new(ApprovalGate::for_red_team()); 
    
    let memory_monitor = Arc::new(MemoryMonitor::new(1024, 2048, None)); // 1GB/2GB limits, no shutdown token for baseline capture
    // BASELINE-HANG-001: memory_semaphore MUST be sized from the same hard_limit_mb
    // the dispatch.rs permits_needed formula reads (memory_monitor.hard_limit_mb()) —
    // matches the pattern in core/orchestrator/mod.rs:23. A hardcoded/mismatched size
    // here let permits_needed exceed the semaphore's real capacity for any plugin with
    // cost >= 6, and Semaphore::acquire_many() has no timeout: that permanently hangs
    // the task (and its concurrency_semaphore slot) with zero warning, eventually
    // starving all 10 concurrency slots and freezing the whole capture silently.
    let memory_semaphore = Arc::new(Semaphore::new(memory_monitor.hard_limit_mb() as usize));
    
    // 2. Define Controlled Targets (matches docker-compose.test.yml)
    let targets = vec![
        // DVWA — web app target for HTTP scanners
        ("http://127.0.0.1:8081".to_string(), TargetType::Web),
        // Samba — host target for network scanners
        ("127.0.0.1:445".to_string(), TargetType::Host),
    ];
    
    let mut all_findings = Vec::new();

    // 3. Run Scans via dispatch_scan
    for (host, target_type) in targets {
        println!("🔍 Scanning: {} (type: {:?})", host, target_type);
        let ip = host.strip_prefix("http://")
            .or_else(|| host.strip_prefix("https://"))
            .unwrap_or(&host)
            .split(':')
            .next()
            .unwrap_or(&host)
            .to_string();
        let target = Arc::new(TargetHost {
            host: host.clone(),
            ip: Some(ip.clone()),
            resolved_ip: Some(ip),
            target_type,
            file_path: None,
            user: None,
            status: TargetStatus::Pending,
            findings: Arc::new(Vec::new()),
            tool_suggestions: Arc::new(Vec::new()),
            tactical_context: Arc::new(serde_json::json!({})),
            extra_data: Arc::new(serde_json::json!({})),
            version: 1,
            skip_heavy_scan: false,
            scan_id: None,
            scope_id: "baseline".to_string(),
        });

        let concurrency_semaphore = Arc::new(Semaphore::new(10));
        let policy = config.policy.clone();
        let strict_scope = false;
        let approval_timeout_secs = None;

        let (findings, _error) = dispatch_scan(
            target.clone(),
            plugins.clone(),
            layer_policy,
            approval_gate.clone(),
            memory_semaphore.clone(),
            memory_monitor.clone(),
            concurrency_semaphore,
            policy,
            strict_scope,
            approval_timeout_secs,
        ).await;

        println!("📥 Captured {} findings from {}", findings.len(), host);
        all_findings.extend(findings);
    }
    
    println!("📊 Capture complete. Total findings: {}", all_findings.len());
    
    // 4. Persistence to tests/baselines/
    let json = serde_json::to_string_pretty(&all_findings)?;
    fs::create_dir_all("tests/baselines")?;
    let path = std::env::current_dir()?.join("tests/baselines/golden_baseline.json");
    fs::write(&path, json)?;
    
    println!("✅ Golden Scan Baseline saved to tests/baselines/golden_baseline.json.");
    Ok(())
}
