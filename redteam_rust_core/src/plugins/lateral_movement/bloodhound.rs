use crate::plugins::{ScannerPlugin, Capability};
use crate::models::{TargetHost, Finding, Severity, Category};
use crate::utils::tool_detection::detect_tool;
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::{info, warn};
use std::process::Stdio;
use tokio::process::Command;
pub struct BloodHoundScanner {
    binary_path: String,
}
impl BloodHoundScanner {
    pub fn new() -> Self {
        let path = which::which("bloodhound-python")
            .unwrap_or_else(|_| "bloodhound-python".into());
        Self {
            binary_path: path.to_string_lossy().to_string(),
        }
    }
}
#[async_trait]
impl ScannerPlugin for BloodHoundScanner {
    fn name(&self) -> &'static str {
        crate::models::PLUGIN_BLOODHOUND
    }
        fn metadata(&self) -> crate::plugins::PluginMetadata {
        crate::plugins::PluginMetadata {
            name: self.name().to_string(),
            description: "Automated security analysis using this plugin.".to_string(),
            target_type: crate::plugins::TargetType::Host,
            risk_level: crate::plugins::RiskLevel::Medium,
            layer: crate::core::capability_layer::ScanLayer::PostExploitation,
            expected_duration: std::time::Duration::from_secs(300),
            capabilities: self.capabilities(),
            cost: 5,
            category: "Lateral Movement".to_string(),
            mitre_attacks: vec![],
            remediation_difficulty: crate::plugins::RiskLevel::Medium,
            blackarch_category: None,
            is_destructive: false,
            poc_mode: false,
        }
    }
    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::ActiveDirectory]
    }
    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability("bloodhound").await)
    }
    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        info!("BloodHoundScanner: collecting AD data from {}", target.host);
        // BloodHound-python collection
        // Note: This usually requires credentials, but here we provide the wrapper structure.
        // We assume credentials are provided via environment variables or a config file in a real scenario.
        let child = Command::new(&self.binary_path)
            .arg("-d")
            .arg(&target.host)
            .arg("-c")
            .arg("All")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .context("Failed to spawn bloodhound-python")?;
        let output = child.wait_with_output().await.context("Failed to wait for BloodHound")?;
        let mut findings = Vec::new();
        let content = String::from_utf8_lossy(&output.stdout);
        if content.contains("Done") || content.contains("Found") {
            findings.push(Finding::new(
                "AD-DATA-COLLECTED",
                Category::Recon,
                Severity::Info,
                &format!("Active Directory data successfully collected from {}. Check output files for BloodHound GUI.", target.host),
                serde_json::json!({ "output": content.trim() })
            ));
        }
        Ok(findings)
    }
}
