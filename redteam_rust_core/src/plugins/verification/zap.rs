use crate::plugins::{ScannerPlugin, Capability};
use crate::models::{TargetHost, Finding, Severity, Category};
use async_trait::async_trait;
use anyhow::Result;
use tracing::{info, warn};
use reqwest::Client;

pub struct ZapScanner {
    api_key: String,
    api_url: String,
    _base_target: String,
}

impl ZapScanner {
    pub fn new(api_key: Option<String>, api_url: Option<String>, base_target: Option<String>) -> Self {
        Self {
            api_key: api_key.unwrap_or_else(|| std::env::var("ZAP_API_KEY").unwrap_or_default()),
            api_url: api_url.unwrap_or_else(|| "http://localhost:8080".into()),
            _base_target: base_target.unwrap_or_default(),
        }
    }
}

#[async_trait]
impl ScannerPlugin for ZapScanner {
    fn name(&self) -> &'static str {
        crate::models::PLUGIN_ZAP
    }

        fn metadata(&self) -> crate::plugins::PluginMetadata {
        crate::plugins::PluginMetadata {
            name: self.name().to_string(),
            description: "OWASP ZAP automated web application security scanner.".to_string(),
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
        Ok(crate::utils::check_tool_availability("zap").await)
    }


    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        info!("ZapScanner: launching scan against {}", target.host);
        
        let client = Client::new();
        let url = if target.host.starts_with("http") {
            target.host.clone()
        } else {
            format!("http://{}", target.host)
        };

        // 1. Start Spider
        let spider_res = client.get(format!("{}/JSON/spider/action/scan/", self.api_url))
            .query(&[("apikey", &self.api_key), ("url", &url)])
            .send().await?;
        
        if !spider_res.status().is_success() {
             warn!("ZapScanner: Failed to start spider for {}", target.host);
             return Ok(Vec::new());
        }

        // 2. Start Active Scan
        let ascan_res = client.get(format!("{}/JSON/ascan/action/scan/", self.api_url))
            .query(&[("apikey", &self.api_key), ("url", &url)])
            .send().await?;

        if !ascan_res.status().is_success() {
             warn!("ZapScanner: Failed to start active scan for {}", target.host);
        }

        // 3. Fetch Alerts (Simplified: in a real professional tool, we'd wait for progress)
        let alerts_res = client.get(format!("{}/JSON/core/view/alerts/", self.api_url))
            .query(&[("apikey", &self.api_key), ("baseurl", &url)])
            .send().await?;

        let alerts_json: serde_json::Value = alerts_res.json().await?;
        let mut findings = Vec::new();

        if let Some(alerts) = alerts_json.get("alerts").and_then(|a| a.as_array()) {
            for alert in alerts {
                let risk = alert.get("risk").and_then(|r| r.as_str()).unwrap_or("Informational");
                let severity = match risk {
                    "High" => Severity::High,
                    "Medium" => Severity::Medium,
                    "Low" => Severity::Low,
                    _ => Severity::Info,
                };

                findings.push(Finding::new(
                    &format!("ZAP-{}", alert.get("id").and_then(|i| i.as_str()).unwrap_or("0")),
                    Category::Vulnerability,
                    severity,
                    alert.get("alert").and_then(|a| a.as_str()).unwrap_or("ZAP Alert"),
                    alert.clone()
                ).with_tactical_path(alert.get("solution").and_then(|s| s.as_str()).unwrap_or("No tactical path identified")));
            }
        }

        Ok(findings)
    }
}
