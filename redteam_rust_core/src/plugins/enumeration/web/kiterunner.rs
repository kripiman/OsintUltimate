use crate::plugins::{ScannerPlugin, Capability};
use crate::models::{TargetHost, Finding, Severity, Category};
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::{info, warn};
use std::process::Stdio;
use tokio::process::Command;

pub struct KiterunnerScanner {
    binary_path: String,
}

impl KiterunnerScanner {
    pub fn new() -> Self {
        let path = which::which("kr").unwrap_or_else(|_| "kr".into());
        Self {
            binary_path: path.to_string_lossy().to_string(),
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
            name: self.name(),
            description: "Automated security analysis using this plugin.",
            target_type: crate::plugins::TargetType::Host,
            risk_level: crate::plugins::RiskLevel::Medium,
            layer: crate::core::capability_layer::ScanLayer::Discovery,
            expected_duration: std::time::Duration::from_secs(300),
            capabilities: self.capabilities(),
            cost: 5,
            category: "Enumeration",
            mitre_attacks: vec![],
            remediation_difficulty: crate::plugins::RiskLevel::Medium,
        }
    }
    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::VulnerabilityScanning]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        Ok(which::which("kiterunner").is_ok())
    }


    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        info!("KiterunnerScanner: launching scan against {}", target.host);

        let url = if target.host.starts_with("http") {
            target.host.clone()
        } else {
            format!("http://{}", target.host)
        };

        let mut child = Command::new(&self.binary_path)
            .arg("scan")
            .arg(&url)
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
