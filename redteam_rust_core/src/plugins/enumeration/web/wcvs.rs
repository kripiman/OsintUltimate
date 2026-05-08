use crate::plugins::{ScannerPlugin, Capability, PluginMetadata, RiskLevel, TargetType};
use crate::models::{TargetHost, Finding, Severity, Category};
use crate::utils::tool_detection::detect_tool;
use crate::core::capability_layer::ScanLayer;
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::info;
use std::process::Stdio;
use tokio::process::Command;

pub struct WcvsScanner {
    binary_path: String,
}

impl Default for WcvsScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl WcvsScanner {
    pub fn new() -> Self {
        let path = detect_tool("web-cache-vuln-scanner");
        Self {
            binary_path: path,
        }
    }
}

#[async_trait]
impl ScannerPlugin for WcvsScanner {
    fn name(&self) -> &'static str {
        "wcvs"
    }

    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: self.name().to_string(),
            description: "Web Cache Vuln Scanner (WCVS): Detects cache poisoning, unkeyed headers, and parameter cloaking.".to_string(),
            target_type: TargetType::Web,
            risk_level: RiskLevel::Safe,
            layer: ScanLayer::Scanning,
            category: "Web".to_string(),
            expected_duration: std::time::Duration::from_secs(180),
            capabilities: vec![Capability::ApiSecurity],
            cost: 3,
            mitre_attacks: vec!["T1190".to_string()], // Initial Access via Exploit Public-Facing Application
            exploit_difficulty: RiskLevel::High,
            ..Default::default()
        }
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::ApiSecurity]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability("web-cache-vuln-scanner").await)
    }

    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        info!("WcvsScanner: checking for web cache poisoning on {}", target.host);

        let base_url = if target.host.starts_with("http") {
            target.host.clone()
        } else {
            format!("https://{}", target.host)
        };

        let child = Command::new(&self.binary_path)
            .arg("-u").arg(&base_url)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to spawn web-cache-vuln-scanner")?;

        let output = child.wait_with_output().await.context("Failed to wait for wcvs")?;
        let mut findings = Vec::new();

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.to_lowercase().contains("vulnerability") || stdout.contains("poison") {
                findings.push(Finding::new(
                    "WEB_CACHE_POISONING",
                    Category::Vulnerability,
                    Severity::High,
                    &format!("Potential Web Cache Poisoning detected at {}", target.host),
                    serde_json::json!({
                        "url": base_url,
                        "raw_output": stdout,
                    })
                ).with_tactical_path("Analyze the unkeyed headers or parameters that influence the response. Test for cross-site scripting (XSS) via cache poisoning."));
            }
        }

        Ok(findings)
    }
}
