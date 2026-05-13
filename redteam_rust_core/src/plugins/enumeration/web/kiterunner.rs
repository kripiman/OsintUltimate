use crate::plugins::{ScannerPlugin, Capability};
use crate::models::{TargetHost, Finding};
use crate::utils::tool_detection::detect_tool;
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::{info, warn};
use std::process::Stdio;
use tokio::process::Command;

pub struct KiterunnerScanner {
    binary_path: String,
}

impl Default for KiterunnerScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl KiterunnerScanner {
    pub fn new() -> Self {
        let path = detect_tool("kr");
        Self {
            binary_path: path,
        }
    }
}

#[async_trait]
impl ScannerPlugin for KiterunnerScanner {
    fn name(&self) -> &'static str {
        "kiterunner"
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
        Ok(crate::utils::check_tool_availability("kiterunner").await)
    }


    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        // V13 HARDENING: Mandatory DNS Pinning (ResolvedIP)
        let pinned_ip = target.pinned_addr()
            .context("DNS Pinning Violation: Kiterunner requires a resolved and pinned IP.")?;
            
        info!("KiterunnerScanner: launching scan against {} (Pinned: {})", target.host, pinned_ip);

        let url = format!("http://{}", pinned_ip);
        let host_header = format!("Host: {}", target.host);

        let mut child = Command::new(&self.binary_path)
            .arg("scan")
            .arg(&url)
            .arg("-H").arg(&host_header)
            .arg("-o").arg("json")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .context("Failed to spawn kiterunner")?;

        let status = child.wait().await.context("Failed to wait for kiterunner")?;

        if !status.success() {
            warn!("Kiterunner failed on {}", target.host);
        }

        // Logic to parse kiterunner JSON output and convert to Finding would go here
        let findings = Vec::new();
        Ok(findings)
    }
}
