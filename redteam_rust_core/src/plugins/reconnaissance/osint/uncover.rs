use crate::plugins::{DiscoveryPlugin, Capability, DiscoveryResult};
use crate::models::TargetHost;
use crate::utils::tool_detection::detect_tool;
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::info;
use std::process::Stdio;
use tokio::process::Command;
pub struct UncoverScanner {
    binary_path: String,
}
impl Default for UncoverScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl UncoverScanner {
    pub fn new() -> Self {
        let path = detect_tool("uncover");
        Self {
            binary_path: path,
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
            name: self.name().to_string(),
            description: "Automated security analysis using this plugin.".to_string(),
            target_type: crate::plugins::TargetType::Osint,
            risk_level: crate::plugins::RiskLevel::Safe,
            layer: crate::core::capability_layer::ScanLayer::Passive,
            expected_duration: std::time::Duration::from_secs(300),
            capabilities: self.capabilities(),
            cost: 5,
            category: "Reconnaissance".to_string(),
            mitre_attacks: vec![],
            exploit_difficulty: crate::plugins::RiskLevel::Medium,
            blackarch_category: None,
            is_destructive: false,
            poc_mode: false, ..Default::default() }
    }
    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::VulnerabilityScanning]
    }
    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability("uncover").await)
    }
    async fn discover(&self, target: &TargetHost) -> Result<Vec<DiscoveryResult>> {
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
                discovered.push(DiscoveryResult { host, metadata: serde_json::json!({}) });
            }
        }
        Ok(discovered)
    }
}
