use crate::plugins::{ScannerPlugin, Capability, PluginMetadata, RiskLevel, TargetType};
use crate::models::{TargetHost, Finding, Severity, Category, constants};
use crate::core::capability_layer::ScanLayer;
use async_trait::async_trait;
use anyhow::Result;
use tracing::info;
use std::time::Duration;

pub struct SecretValidator {
    client: reqwest::Client,
}

impl Default for SecretValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretValidator {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap(),
        }
    }
}

#[async_trait]
impl ScannerPlugin for SecretValidator {
    fn name(&self) -> &'static str { constants::PLUGIN_SECRET_VALIDATOR }

    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: "Secret Validator".to_string(),
            description: "Validates exposed secrets (API keys, tokens) by testing them against known service endpoints.".to_string(),
            target_type: TargetType::Host,
            risk_level: RiskLevel::Safe,
            layer: ScanLayer::Scanning,
            category: "Verification".to_string(),
            capabilities: vec![Capability::VulnerabilityScanning],
            ..Default::default()
        }
    }

    async fn check_dependencies(&self) -> Result<bool> { Ok(true) }
    fn capabilities(&self) -> Vec<Capability> { vec![Capability::VulnerabilityScanning] }

    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        let secret = target.extra_data.get("secret").and_then(|v| v.as_str());
        if secret.is_none() {
            return Ok(Vec::new());
        }
        let secret = secret.unwrap();
        
        info!("🛡️ SECRET-VALIDATOR: Validating exposed secret: {}...", &secret[..std::cmp::min(secret.len(), 8)]);
        
        let mut findings = Vec::new();
        
        // Example: Test for AWS Key
        if secret.starts_with("AKIA") {
            // Test logic here
        }
        
        // Example: Test for GitHub Token
        if secret.starts_with("ghp_") {
            let resp = self.client.get("https://api.github.com/user")
                .header("Authorization", format!("token {}", secret))
                .header("User-Agent", "OsintUltimate")
                .send()
                .await;
                
            if let Ok(r) = resp {
                if r.status().is_success() {
                    let body: serde_json::Value = r.json().await.unwrap_or_default();
                    findings.push(Finding::new(
                        constants::FINDING_EXPOSED_SECRET,
                        Category::Vulnerability,
                        Severity::Critical,
                        "Confirmed LIVE GitHub personal access token exposed!",
                        serde_json::json!({
                            "type": "github_token",
                            "status": "live",
                            "user": body.get("login").and_then(|v| v.as_str()).unwrap_or("unknown"),
                            "user_id": body.get("id").and_then(|v| v.as_u64()).unwrap_or(0)
                        })
                    ));
                }
            }
        }

        Ok(findings)
    }
}
