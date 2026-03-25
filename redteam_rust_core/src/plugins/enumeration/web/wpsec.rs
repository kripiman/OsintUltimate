use crate::plugins::{ScannerPlugin, Capability, PluginMetadata, TargetType, RiskLevel};
use crate::models::{TargetHost, Finding, Severity, Category};
use crate::utils::tool_detection::detect_tool;
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::{info, error, warn};
use std::process::Stdio;
use tokio::process::Command;
use std::time::Duration;

pub struct WPScanner {
    binary_path: String,
}

impl WPScanner {
    pub fn new() -> Self {
        let path = detect_tool("wpscan");
        Self {
            binary_path: path.to_string_lossy().to_string(),
        }
    }
}

#[async_trait]
impl ScannerPlugin for WPScanner {
    fn name(&self) -> &'static str {
        "wp-scanner"
    }

    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: self.name().to_string(),
            description: "WordPress Security Scanner (wpscan integration). Identifies vulnerable plugins, themes, and core versions.".to_string(),
            target_type: TargetType::Web,
            risk_level: RiskLevel::Medium,
            layer: crate::core::capability_layer::ScanLayer::Scanning,
            expected_duration: Duration::from_secs(300),
            capabilities: self.capabilities(),
            cost: 5,
            category: "Enumeration".to_string(),
            mitre_attacks: vec![],
            remediation_difficulty: crate::plugins::RiskLevel::Medium,
            blackarch_category: None,
            is_destructive: false,
            poc_mode: false,
        }
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::VulnerabilityScanning]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability(&self.binary_path).await)
    }

    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        info!("WPScanner: launching scan against {}", target.host);

        let url = if target.host.starts_with("http") {
            target.host.clone()
        } else {
            format!("http://{}", target.host)
        };

        let mut child = Command::new(&self.binary_path)
            .arg("--url").arg(&url)
            .arg("--format").arg("json")
            .arg("--no-banner")
            .arg("--stealthy")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .context("Failed to spawn wpscan")?;

        let output = child.wait_with_output().await.context("Failed to wait for wpscan")?;
        let stdout = String::from_utf8_lossy(&output.stdout);

        let mut findings = Vec::new();

        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
            // Parse WPScan JSON results
            if let Some(version) = json["version"].as_object() {
                if let Some(vulns) = version["vulnerabilities"].as_array() {
                    for v in vulns {
                        findings.push(Finding::new(
                            "WP-CORE-VULN",
                            Category::Vulnerability,
                            Severity::High,
                            v["title"].as_str().unwrap_or("WP Core Vulnerability"),
                            v.clone()
                        ));
                    }
                }
            }
            
            if let Some(plugins) = json["plugins"].as_object() {
                for (name, data) in plugins {
                    if let Some(vulns) = data["vulnerabilities"].as_array() {
                        for v in vulns {
                            findings.push(Finding::new(
                                &format!("WP-PLUGIN-{}", name.to_uppercase()),
                                Category::Vulnerability,
                                Severity::High,
                                v["title"].as_str().unwrap_or("Plugin Vulnerability"),
                                v.clone()
                            ));
                        }
                    }
                }
            }
        }

        Ok(findings)
    }
}
