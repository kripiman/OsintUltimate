use crate::plugins::{ScannerPlugin, Capability};
use crate::models::{TargetHost, Finding, Severity, Category};
use crate::utils::tool_detection::detect_tool;
use async_trait::async_trait;
use anyhow::Result;
use std::sync::Arc;
use tracing::info;
pub struct InteractshScanner {
    binary_path: String,
}
impl Default for InteractshScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl InteractshScanner {
    pub fn new() -> Self {
        let path = detect_tool("interactsh-client");
        Self {
            binary_path: path,
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
            exploit_difficulty: crate::plugins::RiskLevel::Medium,
            blackarch_category: None,
            is_destructive: false,
            poc_mode: false, ..Default::default() }
    }
    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::VulnerabilityScanning]
    }
    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability("interactsh").await)
    }
    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        info!("InteractshScanner: Provisioning OOB environment for {}", target.host);
        
        let oob_mgr = crate::core::verification::interaction::OobInteractionManager::new(
            Arc::new(crate::utils::proxy::ProxyManager::new(Vec::new(), false, crate::utils::config::ProxyMode::Dante, 0))
        );
        
        let oob_id = oob_mgr.generate_id();
        let oob_domain = oob_mgr.get_oob_domain(&oob_id);

        let mut findings = Vec::new();
        findings.push(Finding::new(
            "OOB-TESTING-READY",
            Category::Recon,
            Severity::Info,
            &format!("Interactsh OOB testing environment is ready for target {}. Domain: {}", target.host, oob_domain),
            serde_json::json!({ 
                "binary": self.binary_path,
                "oob_id": oob_id,
                "oob_domain": oob_domain
            })
        ));
        Ok(findings)
    }
}
