use crate::plugins::{ScannerPlugin, Capability};
use crate::models::{TargetHost, Finding, Severity, Category};
use crate::utils::tool_detection::detect_tool;
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::{info, warn};
use std::process::Stdio;
use tokio::process::Command;
pub struct DnsxScanner {
    binary_path: String,
}
impl DnsxScanner {
    pub fn new() -> Self {
        let path = which::which("dnsx")
            .unwrap_or_else(|_| "dnsx".into());
        Self {
            binary_path: path.to_string_lossy().to_string(),
        }
    }
}
#[async_trait]
impl ScannerPlugin for DnsxScanner {
    fn name(&self) -> &'static str {
        "dnsx"
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
            category: "Reconnaissance",
            mitre_attacks: vec![],
            remediation_difficulty: crate::plugins::RiskLevel::Medium,
        }
    }
    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::VulnerabilityScanning]
    }
    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability("dnsx").await)
    }
    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        info!("DnsxScanner: running DNS queries for {}", target.host);
        // dnsx execution
        // -resp-only: Only show results
        // -a, -aaaa, -cname, -ptr, -ns, -mx, -txt, -soa: Query all types
        let mut child = Command::new(&self.binary_path)
            .arg("-d")
            .arg(&target.host)
            .arg("-a")
            .arg("-aaaa")
            .arg("-cname")
            .arg("-ns")
            .arg("-mx")
            .arg("-txt")
            .arg("-resp-only")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .context("Failed to spawn dnsx")?;
        let output = child.wait_with_output().await.context("Failed to wait for dnsx")?;
        let mut findings = Vec::new();
        let content = String::from_utf8_lossy(&output.stdout);
        for line in content.lines() {
            if line.is_empty() { continue; }
            findings.push(Finding::new(
                "DNSX-RECORD",
                Category::Recon,
                Severity::Info,
                &format!("Discovered DNS record: {}", line),
                serde_json::json!({ "record": line.trim() })
            ));
        }
        Ok(findings)
    }
}
