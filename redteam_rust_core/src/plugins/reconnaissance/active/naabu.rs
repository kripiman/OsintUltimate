use crate::plugins::{ScannerPlugin, Capability};
use crate::models::{TargetHost, Finding, Severity, Category};
use crate::utils::tool_detection::detect_tool;
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::info;
use std::process::Stdio;
use tokio::process::Command;
pub struct NaabuScanner {
    binary_path: String,
}
impl Default for NaabuScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl NaabuScanner {
    pub fn new() -> Self {
        let path = detect_tool("naabu");
        Self {
            binary_path: path,
        }
    }
}
#[async_trait]
impl ScannerPlugin for NaabuScanner {
    fn name(&self) -> &'static str {
        crate::models::PLUGIN_NAABU
    }
        fn metadata(&self) -> crate::plugins::PluginMetadata {
        crate::plugins::PluginMetadata {
            name: self.name().to_string(),
            description: "Automated security analysis using this plugin.".to_string(),
            target_type: crate::plugins::TargetType::Network,
            risk_level: crate::plugins::RiskLevel::Medium,
            layer: crate::core::capability_layer::ScanLayer::Discovery,
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
        Ok(crate::utils::check_tool_availability("naabu").await)
    }
    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        info!("NaabuScanner: high-speed port scanning for {}", target.host);
        // naabu execution
        let child = Command::new(&self.binary_path)
            .arg("-host")
            .arg(&target.host)
            .arg("-top-ports")
            .arg("1000")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .context("Failed to spawn naabu")?;
        let output = child.wait_with_output().await.context("Failed to wait for naabu")?;
        let mut findings = Vec::new();
        let content = String::from_utf8_lossy(&output.stdout);
        if !content.is_empty() {
            findings.push(Finding::new(
                "NAABU-PORT-DISCOVERY",
                Category::NetworkPort,
                Severity::Info,
                &format!("High-speed port discovery successful for {} via naabu.", target.host),
                serde_json::json!({ "output": content.trim() })
            ));
        }
        Ok(findings)
    }
}
