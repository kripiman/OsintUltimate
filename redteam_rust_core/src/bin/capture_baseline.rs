use redteam_rust_core::models::{TargetHost, Finding};
use redteam_rust_core::core::Orchestrator;
use redteam_rust_core::core::sink::BufferedSink;
use std::sync::Arc;
use tokio::sync::mpsc;
use std::fs;
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    println!("🚀 Starting REAL Golden Scan Baseline Capture...");
    
    // 1. Setup Buffered Sink
    let sink = BufferedSink::new();
    
    // 2. Setup Orchestrator
    let mut orchestrator = Orchestrator::new(Box::new(sink.clone()));
    
    // 3. Define Controlled Targets (matches docker-compose.test.yml)
    let targets = vec![
        "127.0.0.1:8081".to_string(), // DVWA
        "127.0.0.1:445".to_string(),  // Samba
    ];
    
    // 4. Run Scan
    for target in targets {
        orchestrator.scan(&target).await?;
    }
    
    // 5. Collect Findings
    let findings = sink.get_findings().await;
    println!("📊 Capture complete. Found {} findings.", findings.len());
    
    // 6. Persistence to tests/baselines/ (Non-LFS Path)
    let json = serde_json::to_string_pretty(&findings)?;
    fs::create_dir_all("tests/baselines")?;
    let path = std::env::current_dir()?.join("tests/baselines/golden_baseline.json");
    println!("📝 Writing to: {:?}", path);
    fs::write(&path, json)?;
    
    println!("✅ Golden Scan Baseline saved to tests/baselines/golden_baseline.json.");
    Ok(())
}
