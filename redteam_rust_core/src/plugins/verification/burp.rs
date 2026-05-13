use crate::plugins::{ScannerPlugin, Capability};
use crate::models::{TargetHost, Finding, Severity, Category};
use async_trait::async_trait;
use anyhow::Result;
use tracing::{info, warn};
use reqwest::Client;

pub struct BurpScanner {
    api_key: String,
    api_url: String,
}

impl BurpScanner {
    pub fn new(api_key: Option<String>, api_url: Option<String>) -> Self {
        Self {
            api_key: api_key.unwrap_or_else(|| std::env::var("BURP_API_KEY").unwrap_or_default()),
            api_url: api_url.unwrap_or_else(|| "http://localhost:1337".into()),
        }
    }
}

#[async_trait]
impl ScannerPlugin for BurpScanner {
    fn name(&self) -> &'static str {
        crate::models::PLUGIN_BURP
    }

    
        fn metadata(&self) -> crate::plugins::PluginMetadata {
        crate::plugins::PluginMetadata {
            name: self.name().to_string(),
            description: "Automated security analysis using this plugin.".to_string(),
            target_type: crate::plugins::TargetType::Web,
            risk_level: crate::plugins::RiskLevel::Medium,
            layer: crate::core::capability_layer::ScanLayer::Exploitation,
            expected_duration: std::time::Duration::from_secs(300),
            capabilities: self.capabilities(),
            cost: 5,
            category: "Verification".to_string(),
            mitre_attacks: vec![],
            exploit_difficulty: crate::plugins::RiskLevel::Medium,
            blackarch_category: None,
            is_destructive: false,
            poc_mode: true, ..Default::default() }
    }
    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::VulnerabilityScanning]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability("burp").await)
    }


    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        info!("BurpScanner: launching scan against {}", target.host);
        
        let client = Client::new();
        let url = if target.host.starts_with("http") {
            target.host.clone()
        } else {
            format!("http://{}", target.host)
        };

        // 1. Submit Scan Task (Burp Enterprise/Pro REST API)
        let scan_res = client.post(format!("{}/{}/scan", self.api_url, self.api_key))
            .json(&serde_json::json!({
                "urls": [url],
                "scan_configurations": [{"name": "Crawl and audit - fast"}]
            }))
            .send().await?;
        
        if !scan_res.status().is_success() {
             warn!("BurpScanner: Failed to start scan for {}", target.host);
             return Ok(Vec::new());
        }

        // 2. Fetch Results (Simplified)
        let scan_id = scan_res.headers().get("location").and_then(|l| l.to_str().ok()).unwrap_or("");
        let results_res = client.get(format!("{}{}", self.api_url, scan_id))
            .header("Authorization", &self.api_key)
            .send().await?;

        let results_json: serde_json::Value = results_res.json().await?;
        let mut findings = Vec::new();

        if let Some(issue_events) = results_json.get("issue_events").and_then(|i| i.as_array()) {
            for event in issue_events {
                if let Some(issue) = event.get("issue") {
                    let sev_str = issue.get("severity").and_then(|s| s.as_str()).unwrap_or("info");
                    let severity = match sev_str {
                        "high" => Severity::High,
                        "medium" => Severity::Medium,
                        "low" => Severity::Low,
                        _ => Severity::Info,
                    };

                    findings.push(Finding::new(
                        &format!("BURP-{}", issue.get("type_index").and_then(|i| i.as_u64()).unwrap_or(0)),
                        Category::Vulnerability,
                        severity,
                        issue.get("name").and_then(|n| n.as_str()).unwrap_or("Burp Issue"),
                        issue.clone()
                    ).with_tactical_path(issue.get("remediation").and_then(|r| r.as_str()).unwrap_or("No tactical path identified")));
                }
            }
        }

        Ok(findings)
    }
}
