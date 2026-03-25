use crate::plugins::{ScannerPlugin, Capability};
use crate::models::{TargetHost, Finding, Severity, Category};
use crate::utils::tool_detection::detect_tool;
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::{info, warn};
use std::process::Stdio;
use tokio::process::Command;
pub struct HavocScanner {
    binary_path: String,
}
impl HavocScanner {
    pub fn new() -> Self {
        let path = which::which("havoc")
            .unwrap_or_else(|_| "havoc".into());
        Self {
            binary_path: path.to_string_lossy().to_string(),
        }
    }
}
#[async_trait]
impl ScannerPlugin for HavocScanner {
    fn name(&self) -> &'static str {
        crate::models::PLUGIN_HAVOC
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
            category: "Persistence".to_string(),
            mitre_attacks: vec![],
            remediation_difficulty: crate::plugins::RiskLevel::Medium,
            blackarch_category: None,
            is_destructive: false,
            poc_mode: false,
        }
    }
    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::VulnerabilityScanning]
    }
    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability("havoc").await)
    }
    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        info!("HavocScanner: checking target for C2 compatibility: {}", target.host);
        // Havoc usually involves generating a demon and deploying it.
        // For the scanner, we might check if the target is a known teamserver or if we can generate a payload.
        // Here we implement a generic check/execution wrapper.
        let child = Command::new(&self.binary_path)
            .arg("client") // Example subcommand
            .arg("--host")
            .arg(&target.host)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .context("Failed to spawn havoc")?;
        let output = child.wait_with_output().await.context("Failed to wait for havoc")?;
        let mut findings = Vec::new();
        let content = String::from_utf8_lossy(&output.stdout);
        if content.contains("Connected") || content.contains("Success") {
            findings.push(Finding::new(
                "HAVOC-C2-SUCCESS",
                Category::Vulnerability,
                Severity::Critical,
                &format!("Havoc C2 connection or payload generation successful for {}.", target.host),
                serde_json::json!({ "output": content.trim() })
            ));
        }
        Ok(findings)
    }
}
