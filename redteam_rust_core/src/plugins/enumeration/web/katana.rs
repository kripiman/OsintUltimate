use crate::plugins::{ScannerPlugin, Capability};
use crate::models::{TargetHost, Finding, Severity, Category, FINDING_KATANA_ENDPOINT};
use crate::utils::tool_detection::detect_tool;
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::info;
use std::process::Stdio;
use tokio::process::Command;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct KatanaResult {
    request: KatanaRequest,
    response: Option<KatanaResponse>,
}

#[derive(Debug, Deserialize)]
struct KatanaRequest {
    method: String,
    endpoint: String,
}

#[derive(Debug, Deserialize)]
struct KatanaResponse {
    #[serde(rename = "status_code")]
    status_code: Option<u16>,
}

pub struct KatanaScanner {
    binary_path: String,
}

impl Default for KatanaScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl KatanaScanner {
    pub fn new() -> Self {
        let path = detect_tool("katana");
        Self {
            binary_path: path,
        }
    }
}

#[async_trait]
impl ScannerPlugin for KatanaScanner {
    fn name(&self) -> &'static str {
        crate::models::PLUGIN_KATANA
    }

    
        fn metadata(&self) -> crate::plugins::PluginMetadata {
        crate::plugins::PluginMetadata {
            name: self.name().to_string(),
            description: "Automated security analysis using this plugin.".to_string(),
            target_type: crate::plugins::TargetType::Web,
            risk_level: crate::plugins::RiskLevel::Medium,
            layer: crate::core::capability_layer::ScanLayer::Scanning,
            expected_duration: std::time::Duration::from_secs(300),
            capabilities: self.capabilities(),
            cost: 5,
            category: "Enumeration".to_string(),
            mitre_attacks: vec![],
            exploit_difficulty: crate::plugins::RiskLevel::Medium,
            blackarch_category: None,
            is_destructive: false,
            poc_mode: true, ..Default::default() }
    }
    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::WebFuzzing, Capability::ServiceDiscovery]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability("katana").await)
    }


    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        info!("KatanaScanner: launching scan against {}", target.host);

        let url = if target.host.starts_with("http") {
            target.host.clone()
        } else {
            format!("http://{}", target.host)
        };

        let output = Command::new(&self.binary_path)
            .arg("-u").arg(&url)
            .arg("-jsonl")
            .arg("-silent")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output()
            .await
            .context("Failed to execute katana")?;

        let mut findings = Vec::new();

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if let Ok(res) = serde_json::from_str::<KatanaResult>(line) {
                    findings.push(Finding::new(
                        FINDING_KATANA_ENDPOINT,
                        Category::Recon,
                        Severity::Info,
                        &format!("Discovered endpoint: {} [{}]", res.request.endpoint, res.request.method),
                        serde_json::json!({
                            "method": res.request.method,
                            "endpoint": res.request.endpoint,
                            "status_code": res.response.and_then(|r| r.status_code),
                        })
                    ));
                }
            }
        }

        Ok(findings)
    }
}
