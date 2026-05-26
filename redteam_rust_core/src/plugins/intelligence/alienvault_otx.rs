use crate::plugins::{ScannerPlugin, Capability, TargetType, RiskLevel};
use crate::models::{TargetHost, Finding, Severity, Category};
use crate::utils::config::Config;
use async_trait::async_trait;
use anyhow::Result;
use tracing::{info, warn, error};
use crate::models::constants::*;
use std::time::Duration;

pub struct AlienVaultOtxScanner {
    api_key: Option<String>,
    pub max_ips: usize,
    client: reqwest::Client,
}

impl Default for AlienVaultOtxScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl AlienVaultOtxScanner {
    pub fn new() -> Self {
        let cfg = Config::from_env();
        Self {
            api_key: cfg.alienvault_otx_api_key,
            max_ips: cfg.alienvault_otx_max_ips_per_scan,
            client: reqwest::Client::new(),
        }
    }

    #[cfg(test)]
    pub fn with_key(key: Option<String>, max_ips: usize) -> Self {
        Self { api_key: key, max_ips, client: reqwest::Client::new() }
    }
}

#[async_trait]
impl ScannerPlugin for AlienVaultOtxScanner {
    fn name(&self) -> &'static str {
        PLUGIN_ALIENVAULT_OTX
    }

    fn metadata(&self) -> crate::plugins::PluginMetadata {
        crate::plugins::PluginMetadata {
            name: self.name().to_string(),
            description: "AlienVault OTX intelligence integration for IP reputation and IOC correlation.".to_string(),
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
            poc_mode: true,
            ..Default::default()
        }
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::InformationGathering]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        Ok(self.api_key.is_some())
    }

    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        if self.max_ips == 0 {
            warn!("AlienVaultOtxScanner: max_ips is 0 (disabled). Skipping.");
            return Ok(Vec::new());
        }

        let ip = match &target.ip {
            Some(ip) => ip,
            None => {
                if target.host.parse::<std::net::IpAddr>().is_ok() {
                    &target.host
                } else {
                    return Ok(Vec::new());
                }
            }
        };

        let api_key = match &self.api_key {
            Some(key) => key,
            None => {
                warn!("AlienVaultOtxScanner: ALIENVAULT_OTX_API_KEY not set. Skipping.");
                return Ok(Vec::new());
            }
        };

        info!("AlienVaultOtxScanner: checking IP {}", ip);

        let client = &self.client;
        let url = format!("https://otx.alienvault.com/api/v1/indicators/IPv4/{}/general", ip);

        let response = match client.get(&url)
            .header("X-OTX-API-KEY", api_key)
            .send()
            .await
        {
            Ok(resp) => resp,
            Err(e) => {
                error!("AlienVaultOtxScanner: API error: {}", e);
                return Ok(Vec::new());
            }
        };

        if !response.status().is_success() {
            warn!("AlienVaultOtxScanner: API returned status {}", response.status());
            return Ok(Vec::new());
        }

        let json: serde_json::Value = response.json().await?;
        let mut findings = Vec::new();

        let pulse_count = json.get("pulse_info")
            .and_then(|p| p.get("count"))
            .and_then(|c| c.as_u64())
            .unwrap_or(0);

        if pulse_count > 0 {
            findings.push(Finding::new(
                "IP-INTELLIGENCE",
                Category::Recon,
                Severity::Info,
                &format!("AlienVault OTX for {}: {} pulses", ip, pulse_count),
                serde_json::json!({
                    "ip": ip,
                    "pulse_count": pulse_count,
                    "reputation": json.get("reputation"),
                    "indicator": json.get("indicator"),
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
    fn test_otx_max_ips_propagation() {
        let scanner = AlienVaultOtxScanner::with_key(None, 10);
        assert_eq!(scanner.max_ips, 10);

        let scanner_disabled = AlienVaultOtxScanner::with_key(None, 0);
        assert_eq!(scanner_disabled.max_ips, 0);
    }

    #[tokio::test]
    async fn test_otx_zero_disables_scan() {
        let scanner = AlienVaultOtxScanner::with_key(None, 0);
        let target = TargetHost {
            host: "8.8.8.8".to_string(),
            ip: Some("8.8.8.8".to_string()),
            ..Default::default()
        };
        let findings = scanner.scan(&target).await.unwrap();
        assert!(findings.is_empty());
    }
}
