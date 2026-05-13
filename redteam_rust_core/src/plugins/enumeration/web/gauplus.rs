use crate::plugins::{ScannerPlugin, Capability};
use crate::models::{TargetHost, Finding, Severity, Category};
use crate::utils::tool_detection::detect_tool;
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::info;
use std::process::Stdio;
use tokio::process::Command;
pub struct GauPlusScanner {
    binary_path: String,
}
impl Default for GauPlusScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl GauPlusScanner {
    pub fn new() -> Self {
        let path = detect_tool("gauplus");
        Self {
            binary_path: path,
        }
    }
}
#[async_trait]
impl ScannerPlugin for GauPlusScanner {
    fn name(&self) -> &'static str {
        "gauplus"
    }
        fn metadata(&self) -> crate::plugins::PluginMetadata {
        crate::plugins::PluginMetadata {
            name: self.name().to_string(),
            description: "Automated security analysis using this plugin.".to_string(),
            target_type: crate::plugins::TargetType::Host,
            risk_level: crate::plugins::RiskLevel::Medium,
            layer: crate::core::capability_layer::ScanLayer::Scanning,
            expected_duration: std::time::Duration::from_secs(300),
            capabilities: self.capabilities(),
            cost: 5,
            category: "General".to_string(),
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
        Ok(crate::utils::check_tool_availability("gauplus").await)
    }
    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        info!("GauPlusScanner: discovering historical URLs for {}", target.host);
        // gauplus execution
        // -random-agent: Use a random user agent
        // -t: threads
        let child = Command::new(&self.binary_path)
            .arg("-random-agent")
            .arg(&target.host)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .context("Failed to spawn gauplus")?;
        let output = child.wait_with_output().await.context("Failed to wait for gauplus")?;
        let mut findings = Vec::new();
        let content = String::from_utf8_lossy(&output.stdout);
        let mut count = 0;
        for line in content.lines() {
            if line.is_empty() { continue; }
            count += 1;
            // For historical URLs, we might not want to report every single one if there are thousands.
            // Let's cap it or just report the total count and a few samples if it's too much.
            if count < 50 {
                findings.push(Finding::new(
                    "GAUPLUS-URL-DISCOVERY",
                    Category::Recon,
                    Severity::Info,
                    &format!("Discovered historical URL: {}", line),
                    serde_json::json!({ "url": line.trim() })
                ).with_tactical_path("Review the discovered URL for sensitive parameters or legacy endpoints."));
            }
        }
        if count >= 50 {
             findings.push(Finding::new(
                "GAUPLUS-SUMMARY",
                Category::Recon,
                Severity::Info,
                &format!("GauPlus discovered a total of {} URLs for {}. Showing first 50.", count, target.host),
                serde_json::json!({ "total_count": count })
            ));
        }
        Ok(findings)
    }
}
