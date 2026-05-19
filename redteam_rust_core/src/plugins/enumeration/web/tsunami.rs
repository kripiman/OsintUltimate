use crate::plugins::{ScannerPlugin, Capability};
use crate::models::{TargetHost, Finding, Severity, Category, PLUGIN_TSUNAMI, FINDING_TSUNAMI_VULN};
use crate::utils::tool_detection::detect_tool;
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::{info, warn};
use std::process::Stdio;
use tokio::process::Command;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct TsunamiReport {
    #[serde(default)]
    scan_findings: Vec<TsunamiFinding>,
}

#[derive(Debug, Deserialize)]
struct TsunamiFinding {
    #[serde(rename = "vulnerability")]
    vulnerability: TsunamiVulnerability,
}

#[derive(Debug, Deserialize)]
struct TsunamiVulnerability {
    #[serde(rename = "title")]
    title: String,
    #[serde(rename = "description")]
    description: String,
    #[serde(rename = "severity")]
    severity: String,
}

pub struct TsunamiScanner {
    binary_path: String,
}

impl Default for TsunamiScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl TsunamiScanner {
    pub fn new() -> Self {
        let path = detect_tool("tsunami");
        Self {
            binary_path: path,
        }
    }
}

#[async_trait]
impl ScannerPlugin for TsunamiScanner {
    fn name(&self) -> &'static str {
        PLUGIN_TSUNAMI
    }

    
    fn metadata(&self) -> crate::plugins::PluginMetadata {
        crate::plugins::PluginMetadata {
            name: self.name().to_string(),
            description: "Automated network security analysis using Tsunami.".to_string(),
            category: "Enumeration".to_string(),
            capabilities: self.capabilities(),
            ..crate::plugins::PluginMetadata::default()
        }
    }
    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::VulnerabilityScanning, Capability::PortScanning]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability("tsunami").await)
    }


    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        info!("TsunamiScanner: launching network scan against {}", target.host);

        let temp_file = tempfile::NamedTempFile::new().context("Failed to create temp file for Tsunami")?;
        let temp_path = temp_file.path().to_string_lossy().to_string();

        let mut cmd = Command::new(&self.binary_path);
        cmd.arg(format!("--ip-v4-target={}", target.host))
           .arg("--scan-results-local-output-format=JSON")
           .arg(format!("--scan-results-local-output-path={}", temp_path))
           .stdin(Stdio::null())
           .stdout(Stdio::null())
           .stderr(Stdio::null());

        let status = cmd.spawn()?.wait().await.context("Failed to wait for tsunami")?;

        let mut findings = Vec::new();

        if status.success() {
            if let Ok(content) = tokio::fs::read_to_string(&temp_path).await {
                if let Ok(report) = serde_json::from_str::<TsunamiReport>(&content) {
                    for f in report.scan_findings {
                        let severity = match f.vulnerability.severity.to_uppercase().as_str() {
                            "CRITICAL" => Severity::Critical,
                            "HIGH" => Severity::High,
                            "MEDIUM" => Severity::Medium,
                            _ => Severity::Low,
                        };

                        findings.push(Finding::new(
                            FINDING_TSUNAMI_VULN,
                            Category::Vulnerability,
                            severity,
                            &format!("Tsunami: {}", f.vulnerability.title),
                            serde_json::json!({
                                "description": f.vulnerability.description,
                                "raw_severity": f.vulnerability.severity
                            })
                        ));
                    }
                }
            }
        } else {
            warn!("Tsunami failed on {} with status {:?}", target.host, status.code());
        }

        Ok(findings)
    }
}
