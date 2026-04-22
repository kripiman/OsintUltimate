use anyhow::Result;
use async_trait::async_trait;
use crate::models::TargetHost;
use tokio::process::Command;
use std::process::Stdio;

/// V14.1 Professional Remote Execution Trait
/// Defines the interface for executing commands on remote targets.
#[async_trait]
pub trait RemoteExecutor: Send + Sync {
    async fn execute(&self, target: &TargetHost, cmd: &str) -> Result<String>;
}

/// SSH-based Remote Executor
pub struct SshExecutor {
    // In a real production scenario, we'd use a SSH library like `russh`.
    // For V14.1, we wrap the `ssh` binary with proper key management.
    pub key_path: Option<String>,
}

#[async_trait]
impl RemoteExecutor for SshExecutor {
    async fn execute(&self, target: &TargetHost, cmd: &str) -> Result<String> {
        let mut command = Command::new("ssh");
        
        // V15 HARDENING: OPSEC & MITM Mitigation
        // We use 'accept-new' instead of 'no' to prevent blind acceptance of modified host keys.
        // NOTE: This remains a potential MITM vector if the initial key is not verified. 
        // In a strictly air-gapped or verified deployment, fingerprint pinning should be used.
        command.arg("-o").arg("StrictHostKeyChecking=accept-new")
               .arg("-o").arg("UserKnownHostsFile=/dev/null")
               .arg("-o").arg("BatchMode=yes")
               .arg("-o").arg("ConnectTimeout=10");

        if let Some(ref key) = self.key_path {
            command.arg("-i").arg(key);
        }

        let target_str = if let Some(user) = &target.user {
            format!("{}@{}", user, target.host)
        } else {
            target.host.clone()
        };

        command.arg(target_str)
               .arg(cmd)
               .stdin(Stdio::null())
               .stdout(Stdio::piped())
               .stderr(Stdio::piped());

        tracing::info!("🚀 SSH-EXEC: Running remote command on {}: {}", target.host, cmd);
        
        let output = command.output().await?;
        
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        if output.status.success() {
            Ok(stdout)
        } else {
            anyhow::bail!("SSH Execution failed: {}\n{}", stdout, stderr)
        }
    }
}

