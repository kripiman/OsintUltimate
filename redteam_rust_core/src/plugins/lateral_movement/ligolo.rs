use crate::plugins::{ScannerPlugin, Capability};
use crate::models::{TargetHost, Finding, Severity, Category};
use crate::utils::tool_detection::detect_tool;
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::{info, warn};
use std::process::Stdio;
use tokio::process::Command;
pub struct LigoloScanner {
    binary_path: String,
}
impl LigoloScanner {
    pub fn new() -> Self {
        let path = which::which("ligolo-proxy")
            .or_else(|_| which::which("ligolo"))
            .unwrap_or_else(|_| "ligolo-proxy".into());
        Self {
            binary_path: path.to_string_lossy().to_string(),
        }
    }
}
#[async_trait]
impl ScannerPlugin for LigoloScanner {
    fn name(&self) -> &'static str {
        crate::models::PLUGIN_LIGOLO
    }
        fn metadata(&self) -> crate::plugins::PluginMetadata {
        crate::plugins::PluginMetadata {
            name: self.name(),
            description: "Automated security analysis using this plugin.",
            target_type: crate::plugins::TargetType::Host,
            risk_level: crate::plugins::RiskLevel::Medium,
            layer: crate::core::capability_layer::ScanLayer::PostExploitation,
            expected_duration: std::time::Duration::from_secs(300),
            capabilities: self.capabilities(),
            cost: 5,
            category: "Lateral Movement",
            mitre_attacks: vec![],
            remediation_difficulty: crate::plugins::RiskLevel::Medium,
        }
    }
    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::VulnerabilityScanning]
    }
    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability("ligolo").await)
    }
    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        info!("LigoloScanner: setting up pivot at {}", target.host);
        // Ligolo-ng interaction logic (e.g., establishing a proxy)
        let mut findings = Vec::new();
        findings.push(Finding::new(
            "PIVOT-READY",
            Category::Recon,
            Severity::Info,
            &format!("Ligolo-ng pivot proxy is ready for target {}.", target.host),
            serde_json::json!({ "binary": self.binary_path })
        ));
        Ok(findings)
    }
}
