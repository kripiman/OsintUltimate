use anyhow::{Result, Context};
use std::sync::Arc;
use tokio::process::{Command, Child};
use crate::core::policy::PolicyProvider;
use crate::utils::proxy::ProxyManager;
use tracing::info;
use std::process::Stdio;

/// Marker trait for executor modes.
pub trait ExecutorMode: Send + Sync + 'static {}

/// GHOST mode: Basic stealth execution without remote exploitation capabilities.
pub struct GhostMode;
impl ExecutorMode for GhostMode {}

/// BREACH mode: Advanced execution with mandatory remote coordination capabilities.
pub struct BreachMode;
impl ExecutorMode for BreachMode {}

/// V14.1 Unified Stealth Executor: The only authorized way to interact with OS binaries.
/// Enforces policy-first, proxy-mandatory execution.
/// Generic over the executor mode M for compile-time enforcement of capabilities.
pub struct StealthExecutor<M: ExecutorMode = GhostMode> {
    policy: Arc<dyn PolicyProvider>,
    proxy_manager: Option<Arc<ProxyManager>>,
    stealth_mode: bool,
    remote_executor: Option<Arc<dyn crate::core::validation::remote::RemoteExecutor>>,
    _marker: std::marker::PhantomData<M>,
}

impl StealthExecutor<GhostMode> {
    pub fn new(
        policy: Arc<dyn PolicyProvider>,
        proxy_manager: Option<Arc<ProxyManager>>,
        stealth_mode: bool,
    ) -> Self {
        // V14.1 LEAK-003: Verify proxychains4 availability on construction when stealth_mode is active
        verify_proxychains(stealth_mode);

        Self { 
            policy, 
            proxy_manager, 
            stealth_mode, 
            remote_executor: None,
            _marker: std::marker::PhantomData 
        }
    }
}

#[cfg(feature = "breach-exploit-executor")]
impl StealthExecutor<BreachMode> {
    pub fn new_breach(
        policy: Arc<dyn PolicyProvider>,
        proxy_manager: Option<Arc<ProxyManager>>,
        stealth_mode: bool,
        remote_executor: Arc<dyn crate::core::validation::remote::RemoteExecutor>,
    ) -> Self {
        verify_proxychains(stealth_mode);

        Self { 
            policy, 
            proxy_manager, 
            stealth_mode, 
            remote_executor: Some(remote_executor),
            _marker: std::marker::PhantomData 
        }
    }
}

fn verify_proxychains(stealth_mode: bool) {
    if stealth_mode {
        match std::process::Command::new("proxychains4")
            .arg("-h")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status() 
        {
            Ok(status) if status.success() || status.code() == Some(1) => {
                info!("✅ V14.1 EXECUTOR: 'proxychains4' verified and ready for stealth operations.");
            }
            _ => {
                tracing::error!("⚠️ V14.1 OPSEC CRITICAL: stealth_mode is active but 'proxychains4' was not found or failed to execute. All proxied tool executions will fail.");
            }
        }
    }
}

impl<M: ExecutorMode> StealthExecutor<M> {

    pub fn get_proxy_manager(&self) -> Option<Arc<ProxyManager>> {
        self.proxy_manager.clone()
    }

    /// Validates and executes a binary with stealth wrapping.
    pub async fn spawn(&self, binary: &str, mut args: Vec<String>) -> Result<Child> {
        // 1. Mandatory Policy Check (Fail-Closed)
        self.policy.validate_command(binary, &args)
            .context("V14.1 Security Block: Command failed policy validation.")?;

        info!("🚀 EXECUTOR: Policy verified for '{}'. Preparing execution...", binary);

        // 2. Stealth Wrapping (Proxy Integration)
        let mut final_binary = binary.to_string();
        if let Some(ref pm) = self.proxy_manager {
            if self.stealth_mode || !pm.is_empty() {
                info!("🛡️ EXECUTOR: Wrapping '{}' for stealth deployment...", binary);
                pm.wrap_command(binary, &mut args).context("V14.1 OPSEC Block: Failed to wrap command for stealth.")?;
                
                // Professional Mode logic: If args[0] was tool, it means we want proxychains
                if args.get(0).map(|s| s.as_str()) == Some(binary) {
                    final_binary = "proxychains4".to_string(); // Professional standard
                }
            }
        } else if self.stealth_mode {
            anyhow::bail!("V14.1 OPSEC Violation: Stealth mode active but no ProxyManager available.");
        }

        // 3. Command Construction via common stealth utility
        // Using crate::utils::common::stealth_command if available, or manual construction.
        let mut cmd = Command::new(&final_binary);
        
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

    /// V14.1 Professional Implementation: Dispatches a command to a remote target.
    pub async fn execute_remote(&self, target: &crate::models::TargetHost, cmd: &str) -> Result<String> {
        if let Some(ref re) = self.remote_executor {
            re.execute(target, cmd).await
        } else {
            anyhow::bail!("V14.1 Error: No RemoteExecutor configured in StealthExecutor.")
        }
    }
}
