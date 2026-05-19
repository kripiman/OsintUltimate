use crate::plugins::{ScannerPlugin, Capability, PluginMetadata, RiskLevel, TargetType};
use crate::models::{TargetHost, Finding, Severity, Category, constants};
use crate::core::capability_layer::ScanLayer;
use async_trait::async_trait;
use anyhow::Result;
use tracing::info;
use std::time::Duration;
use serde_json::Value;

pub struct JwksDiscoveryScanner {
    client: reqwest::Client,
}

impl Default for JwksDiscoveryScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl JwksDiscoveryScanner {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .danger_accept_invalid_certs(true)
                .build()
                .unwrap(),
        }
    }
}

#[async_trait]
impl ScannerPlugin for JwksDiscoveryScanner {
    fn name(&self) -> &'static str { constants::PLUGIN_JWKS_DISCOVERY }

    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: "JWKS Discovery".to_string(),
            description: "Discovers JSON Web Key Sets (JWKS) endpoints for JWT security analysis.".to_string(),
            target_type: TargetType::Web,
            risk_level: RiskLevel::Safe,
            layer: ScanLayer::Scanning,
            category: "Enumeration".to_string(),
            expected_duration: Duration::from_secs(30),
            capabilities: vec![Capability::ApiSecurity],
            ..Default::default()
        }
    }

    async fn check_dependencies(&self) -> Result<bool> { Ok(true) }
    fn capabilities(&self) -> Vec<Capability> { vec![Capability::ApiSecurity] }

    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        info!("🔍 JWKS: Scanning common endpoints for {}", target.host);
        let base_url = if target.host.starts_with("http") {
            target.host.clone()
        } else {
            format!("https://{}", target.host)
        };

        let common_paths = [
            "/.well-known/jwks.json",
            "/jwks.json",
            "/openid/v1/jwks",
            "/keys",
            "/.well-known/openid-configuration"
        ];

        let mut findings = Vec::new();

        for path in common_paths {
            let url = format!("{}{}", base_url.trim_end_matches('/'), path);
            if let Ok(resp) = self.client.get(&url).send().await {
                if resp.status().is_success() {
                    let text = resp.text().await.unwrap_or_default();
                    if text.contains("\"keys\"") || text.contains("jwks_uri") {
                        let mut final_url = url.clone();
                        let mut is_config = false;
                        
                        // [S2-4c] Fix: Extract actual jwks_uri from OpenID configuration
                        if path.contains("openid-configuration") {
                            is_config = true;
                            if let Ok(json) = serde_json::from_str::<Value>(&text) {
                                if let Some(jwks_uri) = json.get("jwks_uri").and_then(|v| v.as_str()) {
                                    info!("🔱 JWKS: Extracted jwks_uri {} from OpenID config", jwks_uri);
                                    final_url = jwks_uri.to_string();
                                }
                            }
                        }

                        findings.push(Finding::new(
                            constants::FINDING_JWKS_ENDPOINT,
                            Category::Recon,
                            Severity::Info,
                            &format!("JWKS endpoint discovered at {}", final_url),
                            serde_json::json!({
                                "url": final_url,
                                "discovery_path": path,
                                "type": if is_config { "openid-config" } else { "jwks" }
                            })
                        ));
                    }
                }
            }
        }

        Ok(findings)
    }
}
