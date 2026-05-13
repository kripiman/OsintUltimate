use crate::plugins::{ScannerPlugin, Capability};
use crate::models::{TargetHost, Finding, Severity, Category};
use crate::utils::tool_detection::detect_tool;
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::info;
use std::process::Stdio;
use tokio::process::Command;
pub struct CloudBruteScanner {
    binary_path: String,
}
impl Default for CloudBruteScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl CloudBruteScanner {
    pub fn new() -> Self {
        let path = detect_tool("cloudbrute");
        Self {
            binary_path: path,
        }
    }
}
#[async_trait]
impl ScannerPlugin for CloudBruteScanner {
    fn name(&self) -> &'static str {
        "cloudbrute"
    }
        fn metadata(&self) -> crate::plugins::PluginMetadata {
        crate::plugins::PluginMetadata {
            name: self.name().to_string(),
            description: "Automated security analysis using this plugin.".to_string(),
            target_type: crate::plugins::TargetType::Cloud,
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
        Ok(crate::utils::check_tool_availability("cloudbrute").await)
    }
    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        info!("CloudBruteScanner: scanning for cloud assets for {}", target.host);
        // cloudbrute execution
        // -d: domain
        // -k: keyword (usually domain without TLD)
        let keyword = target.host.split('.').next().unwrap_or(&target.host);
        let child = Command::new(&self.binary_path)
            .arg("-d")
            .arg(&target.host)
            .arg("-k")
            .arg(keyword)
            .arg("-quiet")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .context("Failed to spawn cloudbrute")?;
        let output = child.wait_with_output().await.context("Failed to wait for cloudbrute")?;
        let mut findings = Vec::new();
        let content = String::from_utf8_lossy(&output.stdout);
        for line in content.lines() {
            if line.is_empty() { continue; }
            findings.push(Finding::new(
                "CLOUDBRUTE-ASSET-DISCOVERY",
                Category::Recon,
                Severity::Info,
                &format!("Discovered cloud asset: {}", line),
                serde_json::json!({ "asset": line.trim() })
            ).with_tactical_path("Investigate the discovered cloud asset for sensitive content or misconfigurations."));
        }
        Ok(findings)
    }
}
