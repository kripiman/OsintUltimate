use async_trait::async_trait;
use redteam_rust_core::plugins::{ScannerPlugin, PluginMetadata, PluginStatus, Capability};
use redteam_rust_core::models::{TargetHost, Finding};
use anyhow::Result;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

struct MockMonitor {
    status: Arc<tokio::sync::Mutex<PluginStatus>>,
    stop_called: Arc<AtomicU32>,
}

#[async_trait]
impl ScannerPlugin for MockMonitor {
    fn name(&self) -> &'static str { "mock_monitor" }
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: "mock".to_string(),
            is_monitor: true,
            ..Default::default()
        }
    }
    fn capabilities(&self) -> Vec<Capability> { vec![] }
    async fn check_dependencies(&self) -> Result<bool> { Ok(true) }
    async fn scan(&self, _: &TargetHost) -> Result<Vec<Finding>> { Ok(vec![]) }
    async fn poll_status(&self) -> Result<PluginStatus> {
        Ok(self.status.lock().await.clone())
    }
    async fn stop(&self) -> Result<()> {
        self.stop_called.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[tokio::test]
async fn test_monitor_stop_on_crash() {
    let stop_called = Arc::new(AtomicU32::new(0));
    let status = Arc::new(tokio::sync::Mutex::new(PluginStatus::Crashed("Test crash".to_string())));
    
    let monitor = MockMonitor {
        status: status.clone(),
        stop_called: stop_called.clone(),
    };

    // Simulate Orchestrator logic for one tick
    if let PluginStatus::Crashed(_) = monitor.poll_status().await.unwrap() {
        monitor.stop().await.unwrap();
    }

    assert_eq!(stop_called.load(Ordering::SeqCst), 1);
}
