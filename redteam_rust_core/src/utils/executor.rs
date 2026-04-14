use anyhow::{Result, Context};
use std::sync::Arc;
use tokio::process::{Command, Child};
use crate::core::policy::PolicyProvider;
use crate::utils::proxy::ProxyManager;
use tracing::{info, warn};
use std::process::Stdio;

/// V14.1 Unified Stealth Executor: The only authorized way to interact with OS binaries.
/// Enforces policy-first, proxy-mandatory execution.
pub struct StealthExecutor {
    policy: Arc<dyn PolicyProvider>,
    proxy_manager: Option<Arc<ProxyManager>>,
    stealth_mode: bool,
}

impl StealthExecutor {
    pub fn new(
        policy: Arc<dyn PolicyProvider>,
        proxy_manager: Option<Arc<ProxyManager>>,
        stealth_mode: bool,
    ) -> Self {
        Self { policy, proxy_manager, stealth_mode }
    }

    /// Validates and executes a binary with stealth wrapping.
    pub async fn spawn(&self, binary: &str, mut args: Vec<String>) -> Result<Child> {
        // 1. Mandatory Policy Check (Fail-Closed)
        self.policy.validate_command(binary, &args)
            .context("V14.1 Security Block: Command failed policy validation.")?;

        info!("🚀 EXECUTOR: Policy verified for '{}'. Preparing execution...", binary);

        // 2. Stealth Wrapping (Proxy Integration)
        if let Some(ref pm) = self.proxy_manager {
            if self.stealth_mode || !pm.is_empty() {
                info!("🛡️ EXECUTOR: Wrapping '{}' for stealth deployment...", binary);
                pm.wrap_command(binary, &mut args);
            }
        } else if self.stealth_mode {
            anyhow::bail!("V14.1 OPSEC Violation: Stealth mode active but no ProxyManager available.");
        }

        // 3. Command Construction via common stealth utility
        // Using crate::utils::common::stealth_command if available, or manual construction.
        let mut cmd = Command::new(binary);
        
        // RT-Identity: Neutralize environment variables that could leak identity
        cmd.env_clear()
           .env("PATH", std::env::var("PATH").unwrap_or_default())
           .stdin(Stdio::null())
           .stdout(Stdio::piped())
           .stderr(Stdio::piped());

        cmd.args(&args);

        info!("🔥 EXECUTOR: Spawning process: {} {}", binary, args.join(" "));
        
        cmd.spawn().context(format!("Failed to spawn OS process for tool '{}'", binary))
    }

    /// Executes a command and waits for its output (standardized wrapper).
    pub async fn execute_and_wait(&self, binary: &str, args: Vec<String>) -> Result<std::process::Output> {
        let child = self.spawn(binary, args).await?;
        child.wait_with_output().await.context("Failed to wait for process output")
    }
}
