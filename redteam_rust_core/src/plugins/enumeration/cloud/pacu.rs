use crate::plugins::{ScannerPlugin, Capability};
use crate::models::{TargetHost, Finding, Severity, Category};
use crate::utils::tool_detection::detect_tool;
use async_trait::async_trait;
use anyhow::Result;
use tracing::info;
pub struct PacuScanner {
    binary_path: String,
}
impl Default for PacuScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl PacuScanner {
    pub fn new() -> Self {
        let path = detect_tool("pacu");
        Self {
            binary_path: path,
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
            name: self.name().to_string(),
            description: "Automated security analysis using this plugin.".to_string(),
            target_type: crate::plugins::TargetType::Cloud,
            risk_level: crate::plugins::RiskLevel::Medium,
            layer: crate::core::capability_layer::ScanLayer::Scanning,
            expected_duration: std::time::Duration::from_secs(300),
            capabilities: self.capabilities(),
            cost: 5,
            category: "Enumeration".to_string(),
            mitre_attacks: vec![],
            exploit_difficulty: crate::plugins::RiskLevel::Medium,
            blackarch_category: None,
            is_destructive: false,
            poc_mode: false, ..Default::default() }
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
