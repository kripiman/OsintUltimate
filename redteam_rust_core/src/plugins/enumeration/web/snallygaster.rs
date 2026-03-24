use crate::plugins::{ScannerPlugin, Capability, PluginMetadata, TargetType, RiskLevel};
use crate::models::{TargetHost, Finding, Severity, Category};
use crate::utils::tool_detection::detect_tool;
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::{info, error, warn};
use std::process::Stdio;
use tokio::process::Command;
use std::time::Duration;

pub struct SnallygasterScanner {
    binary_path: String,
}

impl SnallygasterScanner {
    pub fn new() -> Self {
        let path = detect_tool("snallygaster");
        Self {
            binary_path: path.to_string_lossy().to_string(),
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
            name: self.name(),
            description: "Finds secret files on HTTP servers (e.g., .env, .git, config files, backups).",
            target_type: TargetType::Web,
            risk_level: RiskLevel::Low,
            layer: crate::core::capability_layer::ScanLayer::Scanning,
            expected_duration: Duration::from_secs(60),
            capabilities: self.capabilities(),
            cost: 5,
            category: "Enumeration",
            mitre_attacks: vec![],
            remediation_difficulty: crate::plugins::RiskLevel::Medium,
        }
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::SecretDiscovery, Capability::VulnerabilityScanning]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability(&self.binary_path).await)
    }

    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        info!("SnallygasterScanner: launching scan against {}", target.host);

        let mut child = Command::new(&self.binary_path)
            .arg(&target.host)
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
