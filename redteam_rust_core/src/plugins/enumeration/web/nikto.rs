use crate::plugins::{ScannerPlugin, Capability, PluginMetadata, TargetType, RiskLevel};
use crate::models::{TargetHost, Finding, Severity, Category};
use crate::utils::tool_detection::detect_tool;
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::{info, warn};
use std::process::Stdio;
use tokio::process::Command;
use std::time::Duration;

pub struct NiktoScanner {
    binary_path: String,
}

impl Default for NiktoScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl NiktoScanner {
    pub fn new() -> Self {
        let path = detect_tool("nikto");
        Self {
            binary_path: path,
        }
    }
}

#[async_trait]
impl ScannerPlugin for NiktoScanner {
    fn name(&self) -> &'static str {
        "nikto"
    }

    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: self.name().to_string(),
            description: "Classic web server scanner that performs comprehensive tests against web servers for multiple items, including over 6700 potentially dangerous files/programs.".to_string(),
            target_type: TargetType::Web,
            risk_level: RiskLevel::Medium,
            layer: crate::core::capability_layer::ScanLayer::Scanning,
            expected_duration: Duration::from_secs(600),
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
        vec![Capability::VulnerabilityScanning, Capability::WebFuzzing]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability(&self.binary_path).await)
    }

    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        info!("NiktoScanner: launching scan against {}", target.host);

        let url = if target.host.starts_with("http") {
            target.host.clone()
        } else {
            format!("http://{}", target.host)
        };

        // Nikto doesn't have a great JSON output by default in older versions, 
        // but we'll try to use -Format json which outputs to a file.
        let temp_file = tempfile::NamedTempFile::new().context("Failed to create temp file for Nikto")?;
        let temp_path = temp_file.path().to_string_lossy().to_string();

        let mut child = Command::new(&self.binary_path)
            .arg("-h").arg(&url)
            .arg("-Format").arg("json")
            .arg("-o").arg(&temp_path)
            .arg("-Tuning").arg("123457890") // All except DOS
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("Failed to spawn nikto")?;

        let status = child.wait().await.context("Failed to wait for nikto")?;

        if !status.success() {
            warn!("Nikto failed or returned non-zero on {}", target.host);
        }

        let mut findings = Vec::new();

        if let Ok(content) = tokio::fs::read_to_string(&temp_path).await {
            // Nikto JSON format is a bit weird, usually a list of items under "vulnerabilities"
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
                if let Some(vulns) = json["vulnerabilities"].as_array() {
                    for v in vulns {
                        let msg = v["msg"].as_str().unwrap_or("Unknown vulnerability");
                        let id = v["id"].as_str().unwrap_or("NIKTO-GENERIC");
                        
                        findings.push(Finding::new(
                            &format!("NIKTO-{}", id),
                            Category::Vulnerability,
                            Severity::Medium, // Nikto doesn't provide clear severity levels easily
                            msg,
                            v.clone()
                        ));
                    }
                }
            }
        }

        Ok(findings)
    }
}
