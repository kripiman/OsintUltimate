use crate::plugins::{ScannerPlugin, Capability, PluginMetadata, TargetType, RiskLevel};
use crate::models::{TargetHost, Finding, Severity, Category, PLUGIN_JAELES};
use crate::utils::tool_detection::detect_tool;
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::{info, error};
use std::process::Stdio;
use tokio::process::Command;
use std::time::Duration;

pub struct JaelesScanner {
    binary_path: String,
}

impl JaelesScanner {
    pub fn new() -> Self {
        let path = detect_tool("jaeles");
        Self {
            binary_path: path.to_string_lossy().to_string(),
        }
    }
}

#[async_trait]
impl ScannerPlugin for JaelesScanner {
    fn name(&self) -> &'static str {
        PLUGIN_JAELES
    }

    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: self.name(),
            description: "Go-based automation tool for scanning vulnerabilities. Supports custom signatures and high-speed execution.",
            target_type: TargetType::Web,
            risk_level: RiskLevel::Medium,
            layer: crate::core::capability_layer::ScanLayer::Scanning,
            expected_duration: Duration::from_secs(300),
            capabilities: self.capabilities(),
            cost: 5,
            category: "Intelligence",
            mitre_attacks: vec![],
            remediation_difficulty: crate::plugins::RiskLevel::Medium,
        }
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::VulnerabilityScanning]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability("jaeles").await)
    }

    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        info!("JaelesScanner: scanning {}", target.host);
        
        let url = if target.host.starts_with("http") {
            target.host.clone()
        } else {
            format!("http://{}", target.host)
        };

        // Jaeles output is usually to stdout or a file. We'll use a temp file.
        let temp_file = tempfile::NamedTempFile::new().context("Failed to create temp file for Jaeles")?;
        let temp_path = temp_file.path().to_string_lossy().to_string();

        let mut child = Command::new(&self.binary_path)
            .arg("scan")
            .arg("-u").arg(&url)
            .arg("-o").arg(&temp_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("Failed to spawn jaeles")?;

        let _ = child.wait().await?;

        let mut findings = Vec::new();
        // Parse Jaeles output (this is a simplified version, Jaeles has various output formats)
        if let Ok(content) = tokio::fs::read_to_string(&temp_path).await {
            for line in content.lines() {
                if !line.trim().is_empty() {
                    findings.push(Finding::new(
                        "JAELES-VULN",
                        Category::Vulnerability,
                        Severity::Medium,
                        &format!("Vulnerability detected by Jaeles: {}", line),
                        serde_json::json!({"raw": line})
                    ));
                }
            }
        }

        Ok(findings)
    }
}
