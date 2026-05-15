use crate::plugins::{ScannerPlugin, Capability, PluginMetadata, RiskLevel, TargetType};
use crate::models::{TargetHost, Finding, Severity, Category};
use crate::core::capability_layer::ScanLayer;
use crate::utils::tool_detection::detect_tool;
use async_trait::async_trait;
use anyhow::Result;
use tracing::{info, warn};
use tokio::process::Command;
use std::process::Stdio;
use crate::models::constants::*;

pub struct CorsyScanner {
    binary_path: String,
}

impl Default for CorsyScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl CorsyScanner {
    pub fn new() -> Self {
        let path = detect_tool("corsy");
        Self {
            binary_path: path,
        }
    }
}

#[async_trait]
impl ScannerPlugin for CorsyScanner {
    fn name(&self) -> &'static str {
        PLUGIN_CORSY
    }

    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: self.name().to_string(),
            description: "Scanner for CORS misconfigurations (Account Takeover, sensitive data leak).".to_string(),
            target_type: TargetType::Web,
            risk_level: RiskLevel::Low,
            layer: ScanLayer::Scanning,
            category: "Web".to_string(),
            expected_duration: std::time::Duration::from_secs(45),
            capabilities: vec![Capability::VulnerabilityScanning, Capability::ApiSecurity],
            cost: 2,
            mitre_attacks: vec!["T1595.002".to_string()],
            exploit_difficulty: RiskLevel::Low,
            blackarch_category: Some("webapp".to_string()),
            is_destructive: false,
            poc_mode: true, ..Default::default() }
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::VulnerabilityScanning, Capability::ApiSecurity]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability("corsy").await)
    }

    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        info!("CorsyScanner: scanning {}", target.host);
        
        if !self.check_dependencies().await.unwrap_or(false) {
            warn!("CorsyScanner: corsy binary not found. Skipping.");
            return Ok(Vec::new());
        }

        let mut findings = Vec::new();
        
        // 1. Gather base URLs
        let mut base_urls = std::collections::HashSet::new();
        
        let base_url = if target.host.starts_with("http") {
            target.host.clone()
        } else {
            format!("https://{}", target.host)
        };
        base_urls.insert(base_url);

        // Also add interesting subdomains/endpoints found earlier that look like APIs
        for f in target.findings.iter() {
             if let Some(ev) = &f.evidence.primary {
                 for key in ["url", "endpoint", "path"] {
                    if let Some(val) = ev.data.get(key).and_then(|v| v.as_str()) {
                        if val.contains("api") || val.contains("v1") || val.contains("v2") {
                            if let Ok(parsed) = url::Url::parse(val) {
                                let origin = format!("{}://{}", parsed.scheme(), parsed.host_str().unwrap_or(""));
                                base_urls.insert(origin);
                            }
                        }
                    }
                 }
             }
        }

        // Limit to 10 base origins to avoid redundant CORS checks
        for url in base_urls.into_iter().take(10) {
            info!("CorsyScanner: testing origin {}", url);

            let output_res = tokio::time::timeout(
                std::time::Duration::from_secs(45),
                Command::new(&self.binary_path)
                    .arg("-u")
                    .arg(&url)
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .output()
            ).await;

            match output_res {
                Ok(Ok(output)) => {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    // corsy indicators: [VULN] for confirmed, [POSSIBLE] for potential
                    if stdout.contains("[VULN]") || stdout.contains("[POSSIBLE]") || stdout.contains("CORS Misconfiguration") {
                         findings.push(Finding::new(
                            FINDING_CORS_MISCONFIG,
                            Category::Vulnerability,
                            Severity::Medium,
                            &format!("CORS misconfiguration found at {}", url),
                            serde_json::json!({
                                "url": url,
                                "raw_output": stdout.chars().take(1000).collect::<String>(),
                            })
                        ).with_tactical_path("Verify if the misconfiguration allows data leakage (e.g. Access-Control-Allow-Origin: * with Credentials enabled). Check if it's possible to exfiltrate session tokens."));
                    }
                },
                Ok(Err(e)) => warn!("CorsyScanner error for {}: {}", url, e),
                Err(_) => warn!("CorsyScanner timeout for {}", url),
            }
        }

        Ok(findings)
    }
}
