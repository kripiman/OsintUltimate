use crate::plugins::{ScannerPlugin, Capability, PluginMetadata, TargetType, RiskLevel};
use crate::models::{TargetHost, Finding, Severity, Category};
use crate::utils::tool_detection::detect_tool;
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::info;
use std::process::Stdio;
use tokio::process::Command;
use std::time::Duration;

pub struct SnallygasterScanner {
    binary_path: String,
}

impl Default for SnallygasterScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl SnallygasterScanner {
    pub fn new() -> Self {
        let path = detect_tool("snallygaster");
        Self {
            binary_path: path,
        }
    }
}

#[async_trait]
impl ScannerPlugin for SnallygasterScanner {
    fn name(&self) -> &'static str {
        "snallygaster"
    }

    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: self.name().to_string(),
            description: "Finds secret files on HTTP servers (e.g., .env, .git, config files, backups).".to_string(),
            target_type: TargetType::Web,
            risk_level: RiskLevel::Low,
            layer: crate::core::capability_layer::ScanLayer::Scanning,
            expected_duration: Duration::from_secs(60),
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
        vec![Capability::SecretDiscovery, Capability::VulnerabilityScanning]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability(&self.binary_path).await)
    }

    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        // V13 HARDENING: Mandatory DNS Pinning (ResolvedIP)
        let pinned_ip = target.pinned_addr()
            .context("DNS Pinning Violation: Snallygaster requires a resolved and pinned IP to prevent Rebinding.")?;
            
        info!("SnallygasterScanner: launching scan against {} (Pinned: {})", target.host, pinned_ip);

        let child = Command::new(&self.binary_path)
            .arg(pinned_ip)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .context("Failed to spawn snallygaster")?;

        let output = child.wait_with_output().await.context("Failed to wait for snallygaster")?;
        let stdout = String::from_utf8_lossy(&output.stdout);

        let mut findings = Vec::new();

        // Snallygaster usually outputs lines like:
        // [MOD] Found something at http://...
        for line in stdout.lines() {
            if line.contains("Found") || line.contains("at http") {
                findings.push(Finding::new(
                    "SNALLY-DISCOVERY",
                    Category::Vulnerability,
                    Severity::Medium,
                    line,
                    serde_json::json!({ "output": line })
                ));
            }
        }

        Ok(findings)
    }
}
