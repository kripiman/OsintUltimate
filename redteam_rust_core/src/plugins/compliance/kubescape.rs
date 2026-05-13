use crate::plugins::{ScannerPlugin, Capability};
use crate::models::{TargetHost, Finding};
use crate::utils::tool_detection::detect_tool;
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::{info, warn};
use std::process::Stdio;
use tokio::process::Command;

pub struct KubescapeScanner {
    binary_path: String,
}

impl Default for KubescapeScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl KubescapeScanner {
    pub fn new() -> Self {
        let path = detect_tool("kubescape");
        Self {
            binary_path: path,
        }
    }
}

#[async_trait]
impl ScannerPlugin for KubescapeScanner {
    fn name(&self) -> &'static str {
        "kubescape"
    }

    
        fn metadata(&self) -> crate::plugins::PluginMetadata {
        crate::plugins::PluginMetadata {
            name: self.name().to_string(),
            description: "Automated security analysis using this plugin.".to_string(),
            target_type: crate::plugins::TargetType::Cloud,
            risk_level: crate::plugins::RiskLevel::Medium,
            layer: crate::core::capability_layer::ScanLayer::Passive,
            expected_duration: std::time::Duration::from_secs(300),
            capabilities: self.capabilities(),
            cost: 5,
            category: "Compliance".to_string(),
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
        Ok(crate::utils::check_tool_availability("kubescape").await)
    }


    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        info!("KubescapeScanner: scanning cluster/target {}", target.host);

        let mut child = Command::new(&self.binary_path)
            .arg("scan")
            .arg("--format").arg("json")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .context("Failed to spawn kubescape")?;

        let status = child.wait().await.context("Failed to wait for kubescape")?;

        if !status.success() {
            warn!("Kubescape failed on {}", target.host);
        }

        let findings = Vec::new();
        Ok(findings)
    }
}
