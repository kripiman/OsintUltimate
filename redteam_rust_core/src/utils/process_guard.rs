use anyhow::{anyhow, Result};
use std::process::{ExitStatus, Stdio};
use std::time::Duration;
use tracing::{warn, info};
use std::sync::Arc;
use tokio::sync::Mutex;

/// ARCH-10: ExternalToolGuard now tracks a 'KillSwitch' to ensure no zombies
/// even if the parent task is dropped or cancelled mid-execution.
pub struct ExternalToolGuard {
    tool_name: String,
    args: Vec<String>,
    timeout: Duration,
    child_pid: Arc<Mutex<Option<u32>>>,
    proxy_manager: Option<Arc<crate::utils::proxy::ProxyManager>>,
}

impl ExternalToolGuard {
    pub fn new(tool_name: &str, args: &[&str], timeout: Duration, pm: Option<Arc<crate::utils::proxy::ProxyManager>>) -> Self {
        Self {
            tool_name: tool_name.to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
            timeout,
            child_pid: Arc::new(Mutex::new(None)),
            proxy_manager: pm,
        }
    }

    pub async fn run(&self) -> Result<ExitStatus> {
        let mut cmd = crate::utils::common::stealth_command(&self.tool_name, self.proxy_manager.as_ref().map(|p| p.as_ref()));
        cmd.args(&self.args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = cmd.spawn()
            .map_err(|e| anyhow!("Failed to spawn {}: {}", self.tool_name, e))?;
        
        let child_id = child.id().ok_or_else(|| anyhow!("Failed to get child ID"))?;
        
        // Register PID for emergency cleanup
        {
            let mut pid_guard = self.child_pid.lock().await;
            *pid_guard = Some(child_id);
        }

        let result = tokio::select! {
            res = child.wait() => {
                let status = res?;
                info!("Tool {} finished with status: {}", self.tool_name, status);
                Ok(status)
            }
            _ = tokio::time::sleep(self.timeout) => {
                warn!("Tool {} timeout after {:?}, killing PGID {}", self.tool_name, self.timeout, child_id);
                let _ = crate::utils::common::kill_pgid(child_id).await;
                Err(anyhow!("Timeout after {:?}", self.timeout))
            }
        };

        // Cleanup PID after success or expected failure
        let mut pid_guard = self.child_pid.lock().await;
        *pid_guard = None;

        result
    }
}

// Ensure cleanup if dropped during async execution
impl Drop for ExternalToolGuard {
    fn drop(&mut self) {
        // RADICAL CLEANUP: If the guard is dropped and the PID is still set, 
        // it means the task was cancelled or panicked. We MUST spawn a cleanup.
        if let Ok(mut pid_guard) = self.child_pid.try_lock() {
            if let Some(pid) = pid_guard.take() {
                warn!("ExternalToolGuard dropped while tool {} (PID {}) was still running. Terminating...", self.tool_name, pid);
                // Since drop is sync, we spawn a fire-and-forget cleanup task
                tokio::spawn(async move {
                    let _ = crate::utils::common::kill_pgid(pid).await;
                });
            }
        }
    }
}
