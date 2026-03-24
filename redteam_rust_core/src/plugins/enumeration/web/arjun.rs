use crate::plugins::{ScannerPlugin, Capability};
use crate::models::{TargetHost, Finding, Severity, Category};
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::{info, error, warn};
use std::process::Stdio;
use tokio::process::Command;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct ArjunResult {
    params: Vec<String>,
}

pub struct ArjunScanner {
    binary_path: String,
}

impl ArjunScanner {
    pub fn new() -> Self {
        let path = which::which("arjun").unwrap_or_else(|_| "arjun".into());
        Self {
            binary_path: path.to_string_lossy().to_string(),
        }
    }
}

#[async_trait]
impl ScannerPlugin for ArjunScanner {
    fn name(&self) -> &'static str {
        crate::models::PLUGIN_ARJUN
    }

    
        fn metadata(&self) -> crate::plugins::PluginMetadata {
        crate::plugins::PluginMetadata {
            name: self.name(),
            description: "Automated security analysis using this plugin.",
            target_type: crate::plugins::TargetType::Web,
            risk_level: crate::plugins::RiskLevel::Medium,
            layer: crate::core::capability_layer::ScanLayer::Scanning,
            expected_duration: std::time::Duration::from_secs(300),
            capabilities: self.capabilities(),
            cost: 5,
            category: "Enumeration",
            mitre_attacks: vec![],
            remediation_difficulty: crate::plugins::RiskLevel::Medium,
        }
    }
    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::VulnerabilityScanning]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        Ok(which::which("arjun").is_ok())
    }


    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        info!("ArjunScanner: launching scan against {}", target.host);

        let url = if target.host.starts_with("http") {
            target.host.clone()
        } else {
            format!("http://{}", target.host)
        };

        let temp_file = tempfile::NamedTempFile::new().context("Failed to create temp file for Arjun")?;
        let temp_path = temp_file.path().to_string_lossy().to_string();

        let mut child = Command::new(&self.binary_path)
            .arg("-u").arg(&url)
            .arg("-oJ").arg(&temp_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("Failed to spawn arjun")?;

        let status = child.wait().await.context("Failed to wait for arjun")?;

        if !status.success() {
            warn!("Arjun failed on {}", target.host);
        }

        let mut findings = Vec::new();

        if let Ok(content) = tokio::fs::read_to_string(&temp_path).await {
            // Arjun JSON output: {"params": ["id", "user", ...]}
            if let Ok(res) = serde_json::from_str::<serde_json::Value>(&content) {
                if let Some(params) = res.get("params").and_then(|p| p.as_array()) {
                    let param_list: Vec<String> = params.iter().filter_map(|p| p.as_str().map(|s| s.to_string())).collect();
                    if !param_list.is_empty() {
                        findings.push(Finding::new(
                            crate::models::FINDING_TECH_STACK,
                            Category::TechnologyStack,
                            Severity::Info,
                            &format!("Hidden HTTP parameters discovered for {}: {}", url, param_list.join(", ")),
                            serde_json::json!({
                                "url": url,
                                "parameters": param_list,
                            })
                        ));
                    }
                }
            }
        }

        Ok(findings)
    }
}
