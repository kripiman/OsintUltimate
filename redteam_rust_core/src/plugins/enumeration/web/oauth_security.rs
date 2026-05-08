use crate::plugins::{ScannerPlugin, Capability, PluginMetadata, RiskLevel, TargetType};
use crate::models::{TargetHost, Finding, Severity, Category};
use crate::utils::tool_detection::detect_tool;
use crate::core::capability_layer::ScanLayer;
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::info;
use std::process::Stdio;
use tokio::process::Command;

pub struct OAuthScanner {
    binary_path: String,
}

impl Default for OAuthScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl OAuthScanner {
    pub fn new() -> Self {
        let path = detect_tool("oauth-scanner");
        Self {
            binary_path: path,
        }
    }
}

#[async_trait]
impl ScannerPlugin for OAuthScanner {
    fn name(&self) -> &'static str {
        "oauth_security"
    }

    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: self.name().to_string(),
            description: "OAuth Scanner: Detects vulnerabilities in OAuth2 and SAML flows (SSO Misconfigurations).".to_string(),
            target_type: TargetType::Web,
            risk_level: RiskLevel::Safe,
            layer: ScanLayer::Scanning,
            category: "Web".to_string(),
            expected_duration: std::time::Duration::from_secs(120),
            capabilities: vec![Capability::ApiSecurity],
            cost: 3,
            mitre_attacks: vec!["T1550.001".to_string()],
            exploit_difficulty: RiskLevel::High,
            ..Default::default()
        }
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::ApiSecurity]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability("oauth-scanner").await)
    }

    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        info!("OAuthScanner: analyzing OAuth flows for {}", target.host);

        let base_url = if target.host.starts_with("http") {
            target.host.clone()
        } else {
            format!("https://{}", target.host)
        };

        // OAuth scanner typically looks for .well-known/openid-configuration or similar
        let child = Command::new(&self.binary_path)
            .arg("-u").arg(&base_url)
            .arg("-silent")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to spawn oauth-scanner")?;

        let output = child.wait_with_output().await.context("Failed to wait for oauth-scanner")?;
        let mut findings = Vec::new();

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if line.to_lowercase().contains("vulnerability") || line.contains("[!]") {
                    findings.push(Finding::new(
                        "OAUTH_MISCONFIGURATION",
                        Category::Vulnerability,
                        Severity::High,
                        &format!("Potential OAuth/SSO vulnerability at {}", target.host),
                        serde_json::json!({
                            "url": base_url,
                            "output": line,
                        })
                    ).with_tactical_path("Investigate the OAuth redirect_uri, state parameter, and token exchange flow for potential bypasses or leaks."));
                }
            }
        }

        Ok(findings)
    }
}
