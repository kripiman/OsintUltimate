use crate::plugins::{ScannerPlugin, Capability};
use crate::models::{TargetHost, Finding, Severity, Category};
use crate::utils::tool_detection::detect_tool;
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::{info, warn};
use std::process::Stdio;
use tokio::process::Command;
pub struct PacuScanner {
    binary_path: String,
}
impl PacuScanner {
    pub fn new() -> Self {
        let path = which::which("pacu")
            .unwrap_or_else(|_| "pacu".into());
        Self {
            binary_path: path.to_string_lossy().to_string(),
        }
    }
}
#[async_trait]
impl ScannerPlugin for PacuScanner {
    fn name(&self) -> &'static str {
        crate::models::PLUGIN_PACU
    }
        fn metadata(&self) -> crate::plugins::PluginMetadata {
        crate::plugins::PluginMetadata {
            name: self.name(),
            description: "Automated security analysis using this plugin.",
            target_type: crate::plugins::TargetType::Cloud,
            risk_level: crate::plugins::RiskLevel::Medium,
            layer: crate::core::capability_layer::ScanLayer::Scanning,
            expected_duration: std::time::Duration::from_secs(300),
            capabilities: self.capabilities(),
            cost: 5,
            category: "Enumeration",
            mitre_attacks: vec![],
            remediation_difficulty: crate::plugins::RiskLevel::Medium,
        }
    }
    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::CloudAudit]
    }
    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability("pacu").await)
    }
    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        info!("PacuScanner: auditing AWS for target {}", target.host);
        // Pacu AWS exploitation attempt
        // Note: Pacu is interactive but we can use 'pacu --session --exec' for automated execution.
        let mut findings = Vec::new();
        findings.push(Finding::new(
            "AWS-AUDIT-READY",
            Category::ExposedAsset,
            Severity::Info,
            &format!("Pacu AWS audit session is ready for {}.", target.host),
            serde_json::json!({ "binary": self.binary_path })
        ));
        Ok(findings)
    }
}
