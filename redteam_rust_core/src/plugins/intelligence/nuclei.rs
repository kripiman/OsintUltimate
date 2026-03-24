use crate::plugins::{ScannerPlugin, Capability};
use crate::models::{TargetHost, Finding, Severity, Category};
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::{info, error, warn};
use std::process::Stdio;
use tokio::process::Command;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct NucleiResult {
    #[serde(rename = "template-id")]
    template_id: String,
    info: NucleiInfo,
    #[serde(rename = "matched-at")]
    matched_at: String,
}

#[derive(Debug, Deserialize)]
struct NucleiInfo {
    name: String,
    severity: String,
    description: Option<String>,
}

pub struct NucleiScanner {
    binary_path: String,
}

impl NucleiScanner {
    pub fn new() -> Self {
        let path = which::which("nuclei").unwrap_or_else(|_| "nuclei".into());
        Self {
            binary_path: path.to_string_lossy().to_string(),
        }
    }
}

#[async_trait]
impl ScannerPlugin for NucleiScanner {
    fn name(&self) -> &'static str {
        crate::models::PLUGIN_NUCLEI
    }

        fn metadata(&self) -> crate::plugins::PluginMetadata {
        crate::plugins::PluginMetadata {
            name: self.name(),
            description: "Template-based vulnerability scanning using Nuclei. Highly effective for detecting misconfigurations and known CVEs.",
            target_type: crate::plugins::TargetType::Host,
            risk_level: crate::plugins::RiskLevel::Medium,
            layer: crate::core::capability_layer::ScanLayer::Scanning,
            expected_duration: std::time::Duration::from_secs(300),
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
        Ok(which::which("nuclei").is_ok())
    }


    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        info!("NucleiScanner: launching scan against {}", target.host);

        let url = if target.host.starts_with("http") {
            target.host.clone()
        } else {
            format!("http://{}", target.host)
        };

        let temp_file = tempfile::NamedTempFile::new().context("Failed to create temp file for Nuclei")?;
        let temp_path = temp_file.path().to_string_lossy().to_string();

        let mut child = Command::new(&self.binary_path)
            .arg("-u").arg(&url)
            .arg("-jsonl")
            .arg("-o").arg(&temp_path)
            .arg("-silent")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("Failed to spawn nuclei")?;

        let status = child.wait().await.context("Failed to wait for nuclei")?;

        if !status.success() {
            warn!("Nuclei failed on {}", target.host);
            // Nuclei might return 1 if no vulns found in some versions, but usually 0.
            // We proceed to check the file anyway.
        }

        let mut findings = Vec::new();

        if let Ok(content) = tokio::fs::read_to_string(&temp_path).await {
            for line in content.lines() {
                if let Ok(res) = serde_json::from_str::<NucleiResult>(line) {
                    let severity = match res.info.severity.as_str() {
                        "critical" => Severity::Critical,
                        "high" => Severity::High,
                        "medium" => Severity::Medium,
                        "low" => Severity::Low,
                        _ => Severity::Info,
                    };

                    findings.push(Finding::new(
                        &format!("NUCLEI-{}", res.template_id.to_uppercase()),
                        Category::Vulnerability,
                        severity,
                        &format!("{}: {}", res.info.name, res.info.description.unwrap_or_default()),
                        serde_json::json!({
                            "template_id": res.template_id,
                            "matched_at": res.matched_at,
                        })
                    ));
                }
            }
        }

        Ok(findings)
    }
}
