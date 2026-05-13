use crate::plugins::{ScannerPlugin, Capability};
use crate::models::{TargetHost, Finding, Severity, Category};
use crate::utils::tool_detection::detect_tool;
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::{info, error};
use std::process::Stdio;
use tokio::process::Command;
pub struct TrivyScanner {
    binary_path: String,
}
impl Default for TrivyScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl TrivyScanner {
    pub fn new() -> Self {
        let path = detect_tool("trivy");
        Self {
            binary_path: path,
        }
    }
}
#[async_trait]
impl ScannerPlugin for TrivyScanner {
    fn name(&self) -> &'static str {
        "trivy"
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
        Ok(crate::utils::check_tool_availability("trivy").await)
    }
    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        info!("TrivyScanner: scanning {} for container/cloud vulnerabilities", target.host);
        // Trivy can scan many things. Here we try a generic "config" scan or "vm" scan if applicable.
        // For a general target host, we might scan its filesystem or container images if we find them.
        let child = Command::new(&self.binary_path)
            .arg("conf")
            .arg("--format")
            .arg("json")
            .arg(&target.host) // This might not work directly for some hosts without local access
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn();
        let mut findings = Vec::new();
        match child {
            Ok(c) => {
                let output = c.wait_with_output().await.context("Failed to wait for trivy")?;
                if output.status.success() {
                    let content = String::from_utf8_lossy(&output.stdout);
                    if let Ok(json_data) = serde_json::from_str::<serde_json::Value>(&content) {
                        findings.push(Finding::new(
                            "TRIVY-SCAN-RESULT",
                            Category::Misconfiguration,
                            Severity::Info,
                            &format!("Cloud-native security scan completed for {}", target.host),
                            json_data
                        ).with_mitre_attack(vec!["T1584".to_string(), "T1613".to_string()]));
                    }
                }
            }
            Err(e) => {
                error!("TrivyScanner failed to spawn: {}", e);
            }
        }
        Ok(findings)
    }
}
