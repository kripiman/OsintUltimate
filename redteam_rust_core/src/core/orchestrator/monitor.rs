use std::sync::Arc;
use tracing::{info, warn, error};
use crate::models::{Finding, Category, Severity};
use crate::plugins::{ScannerPlugin, PluginStatus};

pub async fn run_monitor_loop(
    plugins: Arc<Vec<Box<dyn ScannerPlugin>>>,
    dashboard_tx: Option<tokio::sync::broadcast::Sender<Finding>>,
    shutdown_token: tokio_util::sync::CancellationToken,
) {
    info!("🛡️  V15.1 MONITOR: Starting lifecycle watcher loop.");
    let mut restart_counts = std::collections::HashMap::new();
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = interval.tick() => {
                for p in plugins.iter() {
                    if p.metadata().is_monitor {
                        match p.poll_status().await {
                            Ok(PluginStatus::Crashed(reason)) => {
                                let count = restart_counts.entry(p.name().to_string()).or_insert(0);
                                if *count < 3 {
                                    warn!("🔄 V15.1 MONITOR: Plugin '{}' crashed ({}). Restarting (Attempt {}/3)...", p.name(), reason, *count + 1);
                                    *count += 1;
                                    
                                    if let Err(e) = p.stop().await {
                                        error!("❌ V15.1 MONITOR: Failed to stop/cleanup plugin '{}': {}", p.name(), e);
                                    }
                                } else {
                                    error!("🚨 V15.1 MONITOR: Plugin '{}' failed 3 times. SUSPENDING.", p.name());
                                    if let Some(ref tx) = dashboard_tx {
                                        let _ = tx.send(Finding::new(
                                            "MONITOR_FAILURE",
                                            Category::Availability,
                                            Severity::Critical,
                                            &format!("Plugin {} suspended after 3 crashes", p.name()),
                                            serde_json::json!({"reason": reason, "plugin": p.name()})
                                        ));
                                    }
                                }
                            }
                            Ok(_) => {
                                restart_counts.insert(p.name().to_string(), 0);
                            }
                            Err(e) => {
                                error!("❌ V15.1 MONITOR: Error polling status for {}: {}", p.name(), e);
                            }
                        }
                    }
                }
            }
            _ = shutdown_token.cancelled() => {
                info!("🛡️  V15.1 MONITOR: Shutdown signal received. Stopping watcher.");
                break;
            }
        }
    }
}
