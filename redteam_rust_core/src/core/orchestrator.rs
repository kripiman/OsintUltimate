use crate::models::{TargetHost, ScanResult, Finding, Severity, Category};
use crate::plugins::ScannerPlugin;
use std::sync::Arc;
use tokio::sync::RwLock; // Tokio RwLock
use tokio::sync::Semaphore;
use tokio::sync::mpsc;
use tracing::{info, error};

pub struct Orchestrator {
    // Plugins are shared across all tasks, protected by RwLock for safe registration
    plugins: Arc<RwLock<Vec<Box<dyn ScannerPlugin>>>>,
    concurrency: usize,
}

impl Orchestrator {
    pub fn new(concurrency: usize) -> Self {
        Self {
            plugins: Arc::new(RwLock::new(Vec::new())),
            concurrency,
        }
    }

    pub async fn register_plugin(&self, plugin: Box<dyn ScannerPlugin>) {
        // Safe registration using key Write Lock (Async)
        self.plugins.write().await.push(plugin);
    }

    pub async fn run(&self, targets: Vec<String>) -> ScanResult {
        // Fix TODO: Real CLI args
        // Redact command line for security (prevent leaking paths/configs in report)
        let cmdline = "redteam_rust_core [REDACTED]".to_string();
        let mut scan_result = ScanResult::new(&cmdline);
        
        let semaphore = Arc::new(Semaphore::new(self.concurrency));
        let (tx, mut rx) = mpsc::channel(100);

        let total_targets = targets.len();
        info!("Starting scan on {} targets with concurrency {}", total_targets, self.concurrency);

        for target_str in targets {
            let plugins_arc = self.plugins.clone();
            
            let sem = semaphore.clone();
            let tx = tx.clone();
            let target_host_str = target_str.clone();

            tokio::spawn(async move {
                // Graceful handling of semaphore acquisition
                let _permit = match sem.acquire().await {
                    Ok(p) => p,
                    Err(e) => {
                        error!("Failed to acquire semaphore for {}: {}", target_host_str, e);
                        return;
                    }
                };
                
                let mut target_host = TargetHost {
                    host: target_host_str.clone(),
                    ip: None,
                    status: "scanning".to_string(),
                    findings: Vec::new(),
                };

                // Acquire Async Read Lock
                // We hold this lock throughout the scan of this host.
                // Since we only possess Read locks during the scan phase, this is fully concurrent.
                let plugins_guard = plugins_arc.read().await;
                
                for plugin in plugins_guard.iter() {
                    match plugin.scan(&mut target_host).await {
                        Ok(_) => {},
                        Err(e) => {
                            error!("Plugin {} failed on {}: {}", plugin.name(), target_host_str, e);
                            target_host.findings.push(Finding::new(
                                "PLUGIN_ERROR",
                                Category::Misconfiguration,
                                Severity::Info, 
                                &format!("Plugin {} failed", plugin.name()),
                                serde_json::json!({"error": e.to_string()})
                            ));
                        }
                    }
                }
                drop(plugins_guard); // Release lock
                
                target_host.status = "scanned".to_string();
                if let Err(e) = tx.send(target_host).await {
                    error!("Failed to send result for {}: {}", target_host_str, e);
                }
            });
        }

        drop(tx);

        while let Some(target_host) = rx.recv().await {
            scan_result.targets.push(target_host);
        }

        info!("Scan completed. Processed {} targets.", scan_result.targets.len());
        scan_result
    }
}
