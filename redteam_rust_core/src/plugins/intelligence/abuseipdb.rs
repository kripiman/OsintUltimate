use crate::plugins::{ScannerPlugin, Capability, TargetType, RiskLevel};
use crate::models::{TargetHost, Finding, Severity, Category};
use async_trait::async_trait;
use anyhow::Result;
use tracing::{info, warn, error};
use crate::models::constants::*;
use std::time::Duration;

pub struct AbuseIPDBScanner {
    api_key: Option<String>,
    pub max_ips: usize,
}

impl Default for AbuseIPDBScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl AbuseIPDBScanner {
    pub fn new() -> Self {
        Self {
            api_key: std::env::var("ABUSEIPDB_API_KEY").ok(),
            max_ips: std::env::var("ABUSEIPDB_MAX_IPS_PER_SCAN")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(50),
        }
    }

    #[cfg(test)]
    pub fn with_key(key: Option<String>, max_ips: usize) -> Self {
        Self { api_key: key, max_ips }
    }
}

#[async_trait]
impl ScannerPlugin for AbuseIPDBScanner {
    fn name(&self) -> &'static str {
        PLUGIN_ABUSEIPDB
    }

    fn metadata(&self) -> crate::plugins::PluginMetadata {
        crate::plugins::PluginMetadata {
            name: self.name().to_string(),
            description: "AbuseIPDB integration for IP reputation and abuse confidence scoring.".to_string(),
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
            warn!("AbuseIPDBScanner: max_ips is 0 (disabled). Skipping.");
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
                warn!("AbuseIPDBScanner: ABUSEIPDB_API_KEY not set. Skipping.");
                return Ok(Vec::new());
            }
        };

        info!("AbuseIPDBScanner: checking IP {}", ip);

        let client = reqwest::Client::new();
        let url = "https://api.abuseipdb.com/api/v2/check";

        let response = match client.get(url)
            .query(&[("ipAddress", ip.as_str()), ("maxAgeInDays", "90")])
            .header("Key", api_key)
            .header("Accept", "application/json")
            .send()
            .await
        {
            Ok(resp) => resp,
            Err(e) => {
                error!("AbuseIPDBScanner: API error: {}", e);
                return Ok(Vec::new());
            }
        };

        if !response.status().is_success() {
            warn!("AbuseIPDBScanner: API returned status {}", response.status());
            return Ok(Vec::new());
        }

        let json: serde_json::Value = response.json().await?;
        let mut findings = Vec::new();

        if let Some(data) = json.get("data") {
            let abuse_score = data.get("abuseConfidencePercentage")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let total_reports = data.get("totalReports")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);

            if abuse_score > 0 || total_reports > 0 {
                let severity = if abuse_score >= 75 {
                    Severity::High
                } else if abuse_score >= 25 {
                    Severity::Medium
                } else {
                    Severity::Info
                };

                findings.push(Finding::new(
                    &format!("IP-REPUTATION-{}", ip),
                    Category::Recon,
                    severity,
                    &format!("AbuseIPDB for {}: abuseConfidence={}, totalReports={}", ip, abuse_score, total_reports),
                    serde_json::json!({
                        "ip": ip,
                        "abuse_confidence_percentage": abuse_score,
                        "total_reports": total_reports,
                        "country_code": data.get("countryCode"),
                        "isp": data.get("isp"),
                        "usage_type": data.get("usageType"),
                    })
                ));
            }
        }

        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_abuseipdb_max_ips_propagation() {
        let scanner = AbuseIPDBScanner::with_key(None, 10);
        assert_eq!(scanner.max_ips, 10);

        let scanner_disabled = AbuseIPDBScanner::with_key(None, 0);
        assert_eq!(scanner_disabled.max_ips, 0);
    }

    #[tokio::test]
    async fn test_abuseipdb_zero_disables_scan() {
        let scanner = AbuseIPDBScanner::with_key(None, 0);
        let target = TargetHost {
            host: "8.8.8.8".to_string(),
            ip: Some("8.8.8.8".to_string()),
            ..Default::default()
        };
        let findings = scanner.scan(&target).await.unwrap();
        assert!(findings.is_empty());
    }
}
