use crate::plugins::{ScannerPlugin, Capability};
use crate::models::{TargetHost, Finding, Severity, Category};
use crate::utils::tool_detection::detect_tool;
use crate::models::constants::*;
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::{info, error, warn};
use std::process::Stdio;
use tokio::process::Command;

pub struct SyftScanner {
    binary_path: String,
}

impl Default for SyftScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl SyftScanner {
    pub fn new() -> Self {
        let path = detect_tool("syft");
        Self {
            binary_path: path,
        }
    }

    fn get_sbom_path(&self, target_host: &str) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        path.push("osint_scans");
        // Sanitize host for filesystem (Windows safe)
        let safe_host = target_host.replace(|c: char| !c.is_alphanumeric() && c != '-', "_");
        path.push(safe_host);
        let _ = std::fs::create_dir_all(&path);
        path.push("sbom.json");
        path
    }
}

#[async_trait]
impl ScannerPlugin for SyftScanner {
    fn name(&self) -> &'static str {
        PLUGIN_SYFT
    }

    fn metadata(&self) -> crate::plugins::PluginMetadata {
        crate::plugins::PluginMetadata {
            name: self.name().to_string(),
            description: "SBOM generator using Syft for deep package inventory analysis.".to_string(),
            target_type: crate::plugins::TargetType::Container,
            risk_level: crate::plugins::RiskLevel::Low,
            layer: crate::core::capability_layer::ScanLayer::Scanning,
            expected_duration: std::time::Duration::from_secs(SUPPLY_TIMEOUT_SYFT_SECS),
            capabilities: vec![Capability::VulnerabilityScanning],
            cost: 5,
            category: "Compliance".to_string(),
            mitre_attacks: vec!["T1584".to_string()],
            exploit_difficulty: crate::plugins::RiskLevel::Low,
            blackarch_category: None,
            is_destructive: false,
            poc_mode: false, ..Default::default() }
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::VulnerabilityScanning]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability("syft").await)
    }

    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        info!("SyftScanner: generating SBOM for container/image: {}", target.host);

        let sbom_path = self.get_sbom_path(&target.host);
        let sbom_path_str = sbom_path.to_string_lossy().to_string();

        let child = Command::new(&self.binary_path)
            .arg(&target.host)
            .arg("-o")
            .arg(format!("json={}", sbom_path_str))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn();

        let mut findings = Vec::new();
        match child {
            Ok(c) => {
                let timeout_duration = std::time::Duration::from_secs(SUPPLY_TIMEOUT_SYFT_SECS);
                let output = match tokio::time::timeout(timeout_duration, c.wait_with_output()).await {
                    Ok(res) => res.context("Failed to wait for syft")?,
                    Err(_) => {
                        warn!("SyftScanner timed out scanning {}", target.host);
                        return Ok(findings);
                    }
                };

                if output.status.success() {
                    // Read the JSON file back for summary
                    if let Ok(content) = tokio::fs::read_to_string(&sbom_path).await {
                        if let Ok(json_data) = serde_json::from_str::<serde_json::Value>(&content) {
                            let total_pkgs = json_data.get("artifacts")
                                .and_then(|v| v.as_array())
                                .map(|a| a.len())
                                .unwrap_or(0);

                            findings.push(Finding::new(
                                FINDING_SBOM_INVENTORY,
                                Category::Compliance,
                                Severity::Info,
                                &format!("SBOM generated for {}: {} packages identified", target.host, total_pkgs),
                                serde_json::json!({
                                    "total_packages": total_pkgs,
                                    "sbom_path": sbom_path_str,
                                    "tool": "syft"
                                })
                            ));
                        }
                    }
                } else {
                    let err = String::from_utf8_lossy(&output.stderr);
                    error!("SyftScanner error: {}", err);
                }
            }
            Err(e) => {
                error!("SyftScanner failed to spawn: {}", e);
            }
        }
        Ok(findings)
    }
}
