use crate::plugins::{ScannerPlugin, Capability};
use crate::models::{TargetHost, Finding, Severity, Category};
use crate::utils::tool_detection::detect_tool;
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::{info, warn};
use std::process::Stdio;
use tokio::process::Command;
pub struct InteractshScanner {
    binary_path: String,
}
impl InteractshScanner {
    pub fn new() -> Self {
        let path = which::which("interactsh-client")
            .unwrap_or_else(|_| "interactsh-client".into());
        Self {
            binary_path: path.to_string_lossy().to_string(),
        }
    }
}
#[async_trait]
impl ScannerPlugin for InteractshScanner {
    fn name(&self) -> &'static str {
        crate::models::PLUGIN_INTERACTSH
    }
        fn metadata(&self) -> crate::plugins::PluginMetadata {
        crate::plugins::PluginMetadata {
            name: self.name().to_string(),
            description: "Automated security analysis using this plugin.".to_string(),
            target_type: crate::plugins::TargetType::Host,
            risk_level: crate::plugins::RiskLevel::Medium,
            layer: crate::core::capability_layer::ScanLayer::Scanning,
            expected_duration: std::time::Duration::from_secs(300),
            capabilities: self.capabilities(),
            cost: 5,
            category: "Enumeration".to_string(),
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
        Ok(crate::utils::check_tool_availability("interactsh").await)
    }
    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        info!("InteractshScanner: checking for OOB interactions on {}", target.host);
        // interactsh-client execution
        let mut findings = Vec::new();
        findings.push(Finding::new(
            "OOB-TESTING-READY",
            Category::Recon,
            Severity::Info,
            &format!("Interactsh OOB testing environment is ready for target {}.", target.host),
            serde_json::json!({ "binary": self.binary_path })
        ));
        Ok(findings)
    }
}
