use crate::plugins::{DiscoveryPlugin, Capability};
use crate::models::TargetHost;
use crate::utils::tool_detection::detect_tool;
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::{info, warn};
use std::process::Stdio;
use tokio::process::Command;
pub struct UncoverScanner {
    binary_path: String,
}
impl UncoverScanner {
    pub fn new() -> Self {
        let path = which::which("uncover")
            .unwrap_or_else(|_| "uncover".into());
        Self {
            binary_path: path.to_string_lossy().to_string(),
        }
    }
}
#[async_trait]
impl DiscoveryPlugin for UncoverScanner {
    fn name(&self) -> &'static str {
        crate::models::PLUGIN_UNCOVER
    }
        fn metadata(&self) -> crate::plugins::PluginMetadata {
        crate::plugins::PluginMetadata {
            name: self.name(),
            description: "Automated security analysis using this plugin.",
            target_type: crate::plugins::TargetType::Osint,
            risk_level: crate::plugins::RiskLevel::Safe,
            layer: crate::core::capability_layer::ScanLayer::Passive,
            expected_duration: std::time::Duration::from_secs(300),
            capabilities: self.capabilities(),
            cost: 5,
            category: "Reconnaissance",
            mitre_attacks: vec![],
            remediation_difficulty: crate::plugins::RiskLevel::Medium,
        }
    }
    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::VulnerabilityScanning]
    }
    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability("uncover").await)
    }
    async fn discover(&self, target: &TargetHost) -> Result<Vec<String>> {
        info!("UncoverScanner: searching OSINT engines for {}", target.host);
        // uncover -q <target> -e shodan,censys,fofa -silent
        let child = Command::new(&self.binary_path)
            .arg("-q")
            .arg(&target.host)
            .arg("-e")
            .arg("shodan,censys,fofa")
            .arg("-silent")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .context("Failed to spawn uncover")?;
        let output = child.wait_with_output().await.context("Failed to wait for uncover")?;
        let mut discovered = Vec::new();
        let content = String::from_utf8_lossy(&output.stdout);
        for line in content.lines() {
            let host = line.trim().to_string();
            if !host.is_empty() {
                discovered.push(host);
            }
        }
        Ok(discovered)
    }
}
