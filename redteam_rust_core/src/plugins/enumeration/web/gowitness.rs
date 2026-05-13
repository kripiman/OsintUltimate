use crate::plugins::{ScannerPlugin, Capability};
use crate::models::{TargetHost, Finding, Severity, Category};
use crate::utils::tool_detection::detect_tool;
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::{info, error};
use std::process::Stdio;
use tokio::process::Command;
pub struct GoWitnessScanner {
    binary_path: String,
}
impl Default for GoWitnessScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl GoWitnessScanner {
    pub fn new() -> Self {
        let path = detect_tool("gowitness");
        Self {
            binary_path: path,
        }
    }
}
#[async_trait]
impl ScannerPlugin for GoWitnessScanner {
    fn name(&self) -> &'static str {
        "gowitness"
    }
        fn metadata(&self) -> crate::plugins::PluginMetadata {
        crate::plugins::PluginMetadata {
            name: self.name().to_string(),
            description: "Automated security analysis using this plugin.".to_string(),
            target_type: crate::plugins::TargetType::Host,
            risk_level: crate::plugins::RiskLevel::Medium,
            layer: crate::core::capability_layer::ScanLayer::Discovery,
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
        Ok(crate::utils::check_tool_availability("gowitness").await)
    }
    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        info!("GoWitnessScanner: starting visual discovery for {}", target.host);
        // gowitness scan single host
        // We use --screenshot-path to define where to save it, but gowitness usually uses a db.
        // For simplicity, we'll try to capture a single screenshot if possible or just run a scan.
        let child = Command::new(&self.binary_path)
            .arg("single")
            .arg("--url")
            .arg(format!("http://{}", target.host)) // Defaulting to http, would be better to check findings
            .arg("--write-db=false")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn();
        let mut findings = Vec::new();
        match child {
            Ok(c) => {
                let output = c.wait_with_output().await.context("Failed to wait for gowitness")?;
                if output.status.success() {
                    findings.push(Finding::new(
                        "GOWITNESS-VISUAL-DISCOVERY",
                        Category::Recon,
                        Severity::Info,
                        &format!("Visual discovery completed for {}. Check gowitness for screenshots.", target.host),
                        serde_json::json!({ "status": "success", "target": target.host })
                    ).with_mitre_attack(vec!["T1595".to_string(), "T1592".to_string()]));
                }
            }
            Err(e) => {
                error!("GoWitnessScanner failed to spawn: {}", e);
            }
        }
        Ok(findings)
    }
}
