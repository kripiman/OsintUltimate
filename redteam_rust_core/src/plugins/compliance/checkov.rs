use crate::plugins::{ScannerPlugin, Capability};
use crate::models::{TargetHost, Finding, Severity, Category, PLUGIN_CHECKOV, FINDING_CHECKOV_MISCONFIG};
use crate::utils::tool_detection::detect_tool;
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::{info, warn};
use std::process::Stdio;
use tokio::process::Command;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct CheckovReport {
    results: CheckovResults,
}

#[derive(Debug, Deserialize)]
struct CheckovResults {
    failed_checks: Vec<CheckovCheck>,
}

#[derive(Debug, Deserialize)]
struct CheckovCheck {
    check_id: String,
    check_name: String,
    file_path: String,
    severity: Option<String>,
}

pub struct CheckovScanner {
    binary_path: String,
}

impl Default for CheckovScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl CheckovScanner {
    pub fn new() -> Self {
        let path = detect_tool("checkov");
        Self {
            binary_path: path,
        }
    }
}

#[async_trait]
impl ScannerPlugin for CheckovScanner {
    fn name(&self) -> &'static str {
        PLUGIN_CHECKOV
    }

    
        fn metadata(&self) -> crate::plugins::PluginMetadata {
        crate::plugins::PluginMetadata {
            name: self.name().to_string(),
            description: "Automated security analysis using this plugin.".to_string(),
            target_type: crate::plugins::TargetType::Cloud,
            risk_level: crate::plugins::RiskLevel::Medium,
            layer: crate::core::capability_layer::ScanLayer::Passive,
            expected_duration: std::time::Duration::from_secs(300),
            capabilities: self.capabilities(),
            cost: 5,
            category: "Compliance".to_string(),
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
        Ok(crate::utils::check_tool_availability("checkov").await)
    }


    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        info!("CheckovScanner: scanning IaC for {}", target.host);

        let mut cmd = Command::new(&self.binary_path);
        
        // If it's a directory, use -d, else -f
        let is_dir = std::path::Path::new(&target.host).is_dir();
        if is_dir {
            cmd.arg("-d").arg(&target.host);
        } else {
            cmd.arg("-f").arg(&target.host);
        }

        cmd.arg("--output").arg("json")
           .arg("--quiet")
           .stdin(Stdio::null())
           .stdout(Stdio::piped())
           .stderr(Stdio::null());

        let output = cmd.spawn()?.wait_with_output().await.context("Failed to wait for checkov")?;

        let mut findings = Vec::new();

        if output.status.success() || output.status.code() == Some(1) { // 1 means checks failed
            let content = String::from_utf8_lossy(&output.stdout);
            
            // Checkov might output an array of reports if multiple frameworks are scanned
            if let Ok(reports) = serde_json::from_str::<Vec<CheckovReport>>(&content) {
                for report in reports {
                    for check in report.results.failed_checks {
                        let severity = match check.severity.unwrap_or_default().to_uppercase().as_str() {
                            "CRITICAL" => Severity::Critical,
                            "HIGH" => Severity::High,
                            "MEDIUM" => Severity::Medium,
                            _ => Severity::Low,
                        };
                        findings.push(Finding::new(
                            FINDING_CHECKOV_MISCONFIG,
                            Category::Misconfiguration,
                            severity,
                            &format!("Checkov: {} ({}) in {}", check.check_name, check.check_id, check.file_path),
                            serde_json::json!({
                                "check_id": check.check_id,
                                "file_path": check.file_path
                            })
                        ));
                    }
                }
            } else if let Ok(report) = serde_json::from_str::<CheckovReport>(&content) {
                 for check in report.results.failed_checks {
                    let severity = match check.severity.unwrap_or_default().to_uppercase().as_str() {
                            "CRITICAL" => Severity::Critical,
                            "HIGH" => Severity::High,
                            "MEDIUM" => Severity::Medium,
                            _ => Severity::Low,
                        };
                        findings.push(Finding::new(
                            FINDING_CHECKOV_MISCONFIG,
                            Category::Misconfiguration,
                            severity,
                            &format!("Checkov: {} ({}) in {}", check.check_name, check.check_id, check.file_path),
                            serde_json::json!({
                                "check_id": check.check_id,
                                "file_path": check.file_path
                            })
                        ));
                 }
            }
        } else {
            warn!("Checkov failed on {} with status {:?}", target.host, output.status.code());
        }

        Ok(findings)
    }
}
