use crate::plugins::{ScannerPlugin, Capability};
use crate::models::{TargetHost, Finding, Severity, Category};
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::{info, warn};
use std::process::Stdio;
use tokio::process::Command;

pub struct SliverScanner {
    binary_path: String,
}

impl SliverScanner {
    pub fn new() -> Self {
        let path = which::which("sliver-server")
            .or_else(|_| which::which("sliver"))
            .unwrap_or_else(|_| "sliver-server".into());
            
        Self {
            binary_path: path.to_string_lossy().to_string(),
        }
    }
}

#[async_trait]
impl ScannerPlugin for SliverScanner {
    fn name(&self) -> &'static str {
        crate::models::PLUGIN_SLIVER
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
        Ok(which::which("sliver").is_ok())
    }


    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        info!("SliverScanner: preparing C2 implant for {}", target.host);

        // Sliver C2 interaction (e.g., generating an implant)
        // This is a placeholder for actual Sliver interaction logic.
        let mut findings = Vec::new();

        findings.push(Finding::new(
            "C2-INFRASTRUCTURE-READY",
            Category::Vulnerability,
            Severity::Info,
            &format!("Sliver C2 infrastructure is ready for target {}.", target.host),
            serde_json::json!({ "binary": self.binary_path })
        ));

        Ok(findings)
    }
}
