use crate::plugins::{ScannerPlugin, Capability};
use crate::models::{TargetHost, Finding, Severity, Category};
use crate::utils::tool_detection::detect_tool;
use crate::models::constants::*;
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::{info, error, warn};
use std::process::Stdio;
use tokio::process::Command;

pub struct GrypeScanner {
    binary_path: String,
}

impl Default for GrypeScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl GrypeScanner {
    pub fn new() -> Self {
        let path = detect_tool("grype");
        Self {
            binary_path: path,
        }
    }

    fn get_sbom_path(&self, target_host: &str) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        path.push("osint_scans");
        let safe_host = target_host.replace(|c: char| !c.is_alphanumeric() && c != '-', "_");
        path.push(safe_host);
        path.push("sbom.json");
        path
    }
}

#[async_trait]
impl ScannerPlugin for GrypeScanner {
    fn name(&self) -> &'static str {
        PLUGIN_GRYPE
    }

    fn metadata(&self) -> crate::plugins::PluginMetadata {
        crate::plugins::PluginMetadata {
            name: self.name().to_string(),
            description: "Vulnerability scanner using Grype. Faster and deeper CVE mapping for container images.".to_string(),
            target_type: crate::plugins::TargetType::Container,
            risk_level: crate::plugins::RiskLevel::Medium,
            layer: crate::core::capability_layer::ScanLayer::Scanning,
            expected_duration: std::time::Duration::from_secs(SUPPLY_TIMEOUT_GRYPE_SECS),
            capabilities: vec![Capability::VulnerabilityScanning],
            cost: 8,
            category: "Compliance".to_string(),
            mitre_attacks: vec!["T1588.006".to_string()],
            exploit_difficulty: crate::plugins::RiskLevel::Medium,
            blackarch_category: None,
            is_destructive: false,
            poc_mode: false, ..Default::default() }
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::VulnerabilityScanning]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability("grype").await)
    }

    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        info!("GrypeScanner: scanning {} for vulnerabilities", target.host);

        let sbom_path = self.get_sbom_path(&target.host);
        let input_arg = if sbom_path.exists() {
            format!("sbom:{}", sbom_path.to_string_lossy())
        } else {
            target.host.clone()
        };

        let child = Command::new(&self.binary_path)
            .arg(input_arg)
            .arg("-o")
            .arg("json")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn();

        let mut findings = Vec::new();
        match child {
            Ok(c) => {
                let timeout_duration = std::time::Duration::from_secs(SUPPLY_TIMEOUT_GRYPE_SECS);
                let output = match tokio::time::timeout(timeout_duration, c.wait_with_output()).await {
                    Ok(res) => res.context("Failed to wait for grype")?,
                    Err(_) => {
                        warn!("GrypeScanner timed out scanning {}", target.host);
                        return Ok(findings);
                    }
                };

                if output.status.success() {
                    let content = String::from_utf8_lossy(&output.stdout);
                    if let Ok(json_data) = serde_json::from_str::<serde_json::Value>(&content) {
                        let matches = json_data.get("matches").and_then(|m| m.as_array());
                        
                        if let Some(matches_arr) = matches {
                            for m in matches_arr {
                                let vuln = m.get("vulnerability");
                                let artifact = m.get("artifact");
                                
                                if let (Some(v), Some(a)) = (vuln, artifact) {
                                    let id = v.get("id").and_then(|v| v.as_str()).unwrap_or("UNKNOWN-CVE");
                                    let severity_str = v.get("severity").and_then(|v| v.as_str()).unwrap_or("Unknown");
                                    let pkg_name = a.get("name").and_then(|v| v.as_str()).unwrap_or("unknown");
                                    let pkg_version = a.get("version").and_then(|v| v.as_str()).unwrap_or("unknown");
                                    
                                    let severity = match severity_str.to_lowercase().as_str() {
                                        "critical" => Severity::Critical,
                                        "high" => Severity::High,
                                        "medium" => Severity::Medium,
                                        "low" => Severity::Low,
                                        _ => Severity::Info,
                                    };

                                    findings.push(Finding::new(
                                        FINDING_SUPPLY_CHAIN_VULN,
                                        Category::Vulnerability,
                                        severity,
                                        &format!("{} found in {}@{}", id, pkg_name, pkg_version),
                                        m.clone()
                                    ).with_mitre_attack(vec!["T1588.006".to_string()]));
                                }
                            }
                        }
                    }
                } else {
                    let err = String::from_utf8_lossy(&output.stderr);
                    error!("GrypeScanner error: {}", err);
                }
            }
            Err(e) => {
                error!("GrypeScanner failed to spawn: {}", e);
            }
        }
        Ok(findings)
    }
}
