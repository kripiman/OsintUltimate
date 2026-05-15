use crate::models::{Finding, Category, Severity, TargetHost, TargetType, constants::*};
use std::sync::RwLock;
use crate::plugins::{ScannerPlugin, Capability, PluginMetadata, RiskLevel};
use async_trait::async_trait;
use chrono::{DateTime, Utc, Duration};
use anyhow::Result;
use tracing::{info, warn};
use serde_json::json;

pub struct NvdMonitor {
    last_check: RwLock<DateTime<Utc>>,
    api_key: Option<String>,
}

impl NvdMonitor {
    pub fn new(api_key: Option<String>) -> Self {
        Self {
            last_check: RwLock::new(Utc::now() - Duration::hours(24)),
            api_key,
        }
    }

    pub async fn poll(&self) -> Result<Vec<Finding>> {
        let client = reqwest::Client::new();
        let now = Utc::now();
        
        let start_date = self.last_check.read().unwrap().format("%Y-%m-%dT%H:%M:%S").to_string();
        let end_date = now.format("%Y-%m-%dT%H:%M:%S").to_string();

        info!("🛡️ V14.6 INTEL: Polling NVD for new CVEs ({} to {})...", start_date, end_date);

        let url = format!(
            "https://services.nvd.nist.gov/rest/json/cves/2.0/?pubStartDate={}&pubEndDate={}",
            start_date, end_date
        );

        let mut request = client.get(&url);
        if let Some(key) = &self.api_key {
            request = request.header("apiKey", key);
        }

        let resp = request.send().await?;
        if !resp.status().is_success() {
            warn!("🛡️ V14.6 INTEL: NVD API returned status {}", resp.status());
            return Ok(Vec::new());
        }

        let body: serde_json::Value = resp.json().await?;
        let mut findings = Vec::new();

        if let Some(vulnerabilities) = body.get("vulnerabilities").and_then(|v| v.as_array()) {
            info!("🛡️ V14.6 INTEL: Found {} new CVEs in NVD.", vulnerabilities.len());
            for v in vulnerabilities {
                if let Some(cve) = v.get("cve") {
                    let id = cve.get("id").and_then(|i| i.as_str()).unwrap_or("Unknown");
                    let description = cve.get("descriptions")
                        .and_then(|d| d.as_array())
                        .and_then(|d| d.first())
                        .and_then(|d| d.get("value"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("No description available.");

                    findings.push(Finding::new(
                        FINDING_NEW_CVE_DISCOVERED,
                        Category::Recon,
                        Severity::Info,
                        &format!("NVD: New CVE Published - {}", id),
                        json!({
                            "cve_id": id,
                            "description": description,
                            "source": "NVD",
                        })
                    ).with_references(vec![format!("https://nvd.nist.gov/vuln/detail/{}", id)]));
                }
            }
        }

        if let Ok(mut lock) = self.last_check.write() {
            *lock = now;
        }
        Ok(findings)
    }
}

#[async_trait]
impl ScannerPlugin for NvdMonitor {
    fn name(&self) -> &'static str {
        PLUGIN_NVD_MONITOR
    }

    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: self.name().to_string(),
            description: "Real-time NVD CVE monitor and intelligence feed.".to_string(),
            target_type: TargetType::Osint,
            risk_level: RiskLevel::Safe,
            layer: crate::core::capability_layer::ScanLayer::Passive,
            expected_duration: std::time::Duration::from_secs(60),
            capabilities: vec![Capability::OsintDiscovery, Capability::InformationGathering],
            cost: 0,
            category: "Intelligence".to_string(),
            is_monitor: true,
            ..Default::default()
        }
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::OsintDiscovery, Capability::InformationGathering]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        Ok(true)
    }

    async fn scan(&self, _target: &TargetHost) -> Result<Vec<Finding>> {
        // [N-4] Rate-limit: only poll NVD once per hour to avoid API bans
        {
            let last = self.last_check.read().unwrap();
            if Utc::now() - *last < chrono::Duration::hours(1) {
                return Ok(Vec::new());
            }
        }
        self.poll().await
    }
}
