use crate::plugins::{ScannerPlugin, Capability};
use crate::models::{TargetHost, Finding, Severity, Category};
use crate::utils::tool_detection::detect_tool;
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::info;
use std::process::Stdio;
use tokio::process::Command;

pub struct RustScanScanner {
    binary_path: String,
}

impl Default for RustScanScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl RustScanScanner {
    pub fn new() -> Self {
        let path = detect_tool("rustscan");
        Self {
            binary_path: path,
        }
    }
}

#[async_trait]
impl ScannerPlugin for RustScanScanner {
    fn name(&self) -> &'static str {
        crate::models::PLUGIN_RUSTSCAN
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
            category: "Enumeration".to_string(),
            mitre_attacks: vec!["T1046".to_string()],
            exploit_difficulty: crate::plugins::RiskLevel::Low,
            blackarch_category: Some("scanner".to_string()),
            is_destructive: false,
            poc_mode: true, ..Default::default() }
    }
    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::PortScanning]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability("rustscan").await)
    }


    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        let target_addr = target.pinned_addr()?;
        info!("RustScanScanner: scanning ports for {}", target_addr);

        // RustScan is extremely fast. We pass -a target and let it find open ports.
        // Then we can optionally pass those to nmap, but here we'll just report open ports found by rustscan.
        let child = Command::new(&self.binary_path)
            .arg("-a").arg(target_addr)
            .arg("--ulimit").arg("5000")
            .arg("--quiet")
            .arg("--") // RustScan flags end here, then come nmap flags
            .arg("-sV") // Service version detection in the final nmap scan
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .context("Failed to spawn rustscan")?;

        let output = child.wait_with_output().await.context("Failed to wait for rustscan")?;

        let mut findings = Vec::new();
        let content = String::from_utf8_lossy(&output.stdout);
        
        // Basic parsing of rustscan/nmap output to find open ports
        for line in content.lines() {
            if line.contains("/tcp") && line.contains("open") {
                findings.push(Finding::new(
                    crate::models::FINDING_PORT_OPEN,
                    Category::NetworkPort,
                    Severity::Low,
                    &format!("RustScan detected an open port on {}: {}", target_addr, line.trim()),
                    serde_json::json!({ "output": line.trim() })
                ));
            }
        }

        Ok(findings)
    }
}
