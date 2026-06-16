use crate::plugins::{ScannerPlugin, Capability, TargetType, RiskLevel};
use crate::models::{TargetHost, Finding, Severity, Category};
use crate::utils::config::Config;
use async_trait::async_trait;
use anyhow::Result;
use tracing::{info, warn, error};
use crate::models::constants::*;
use std::time::Duration;
use tokio::sync::Mutex;
use std::sync::Arc;

lazy_static::lazy_static! {
    static ref GREYNOISE_RATE_LIMITER: Arc<Mutex<()>> = Arc::new(Mutex::new(()));
}

pub struct GreyNoiseScanner {
    api_key: Option<String>,
    pub max_ips: usize,
    client: reqwest::Client,
}

impl Default for GreyNoiseScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl GreyNoiseScanner {
    pub fn new() -> Self {
        let cfg = Config::from_env();
        Self {
            api_key: cfg.greynoise_api_key,
            max_ips: cfg.greynoise_max_ips_per_scan,
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl ScannerPlugin for GreyNoiseScanner {
    fn name(&self) -> &'static str {
        PLUGIN_GREYNOISE
    }

    fn metadata(&self) -> crate::plugins::PluginMetadata {
        crate::plugins::PluginMetadata {
            name: self.name().to_string(),
            description: "GreyNoise Intelligence integration to identify internet background noise and scanners.".to_string(),
            target_type: TargetType::Host,
            risk_level: RiskLevel::Safe,
            layer: crate::core::capability_layer::ScanLayer::Passive,
            expected_duration: Duration::from_secs(5),
            capabilities: vec![Capability::InformationGathering],
            cost: 1,
            category: "Intelligence".to_string(),
            mitre_attacks: vec!["T1592".to_string()],
            exploit_difficulty: RiskLevel::Safe,
            blackarch_category: Some("recon".to_string()),
            is_destructive: false,
            poc_mode: true, ..Default::default() }
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::InformationGathering]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        Ok(self.api_key.is_some())
    }

    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        if self.max_ips == 0 {
            warn!("GreyNoiseScanner: max_ips is 0 (disabled). Skipping.");
            return Ok(Vec::new());
        }

        let ip = match &target.ip {
            Some(ip) => ip,
            None => {
                // If target host is an IP, use it
                if target.host.parse::<std::net::IpAddr>().is_ok() {
                    &target.host
                } else {
                    return Ok(Vec::new());
                }
            }
        };

        info!("GreyNoiseScanner: checking IP {}", ip);
        
        let api_key = match &self.api_key {
            Some(key) => key,
            None => {
                warn!("GreyNoiseScanner: GREYNOISE_API_KEY not set. Skipping.");
                return Ok(Vec::new());
            }
        };

        let client = &self.client;
        let url = format!("https://api.greynoise.io/v3/community/{}", ip);
        
        // Strict Rate Limiting (OPSEC): Global lock across all worker threads.
        // Even with --concurrency 4, only one thread can hold this lock at a time.
        // It holds the lock, sleeps for 2 seconds, then releases it, guaranteeing max 30 RPM globally.
        let _lock = GREYNOISE_RATE_LIMITER.lock().await;
        tokio::time::sleep(Duration::from_secs(2)).await;
        
        let response = match client.get(&url)
            .header("key", api_key)
            .send()
            .await {
                Ok(resp) => resp,
                Err(e) => {
                    error!("GreyNoiseScanner: API error: {}", e);
                    return Ok(Vec::new());
                }
            };

        if response.status() == 404 {
            // Not found in GreyNoise
            return Ok(Vec::new());
        }

        if !response.status().is_success() {
            warn!("GreyNoiseScanner: API returned status {}", response.status());
            return Ok(Vec::new());
        }

        let json: serde_json::Value = response.json().await?;
        let noise = json.get("noise").and_then(|n| n.as_bool()).unwrap_or(false);
        let riot = json.get("riot").and_then(|r| r.as_bool()).unwrap_or(false);

        let mut findings = Vec::new();
        if noise || riot {
            findings.push(Finding::new(
                "IP-INTELLIGENCE",
                Category::Recon,
                Severity::Info,
                &format!("GreyNoise Intelligence for {}: Noise={}, RIOT={}", ip, noise, riot),
                serde_json::json!({
                    "ip": ip,
                    "noise": noise,
                    "riot": riot,
                    "classification": json.get("classification"),
                    "name": json.get("name"),
                    "last_seen": json.get("last_seen"),
                })
            ));
        }

        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_greynoise_max_ips_propagation() {
        std::env::set_var("GREYNOISE_MAX_IPS_PER_SCAN", "10");
        let scanner = GreyNoiseScanner::new();
        assert_eq!(scanner.max_ips, 10);

        std::env::set_var("GREYNOISE_MAX_IPS_PER_SCAN", "0");
        let scanner_disabled = GreyNoiseScanner::new();
        assert_eq!(scanner_disabled.max_ips, 0);

        std::env::remove_var("GREYNOISE_MAX_IPS_PER_SCAN");
    }

    #[tokio::test]
    async fn test_greynoise_zero_disables_scan() {
        let mut scanner = GreyNoiseScanner::new();
        scanner.max_ips = 0;
        let target = TargetHost {
            host: "8.8.8.8".to_string(),
            ip: Some("8.8.8.8".to_string()),
            ..Default::default()
        };
        let findings = scanner.scan(&target).await.unwrap();
        assert!(findings.is_empty());
    }
}
