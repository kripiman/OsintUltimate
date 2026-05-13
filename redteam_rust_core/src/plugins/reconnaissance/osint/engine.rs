use crate::plugins::{DiscoveryPlugin, Capability, DiscoveryResult};
use crate::models::TargetHost;
use async_trait::async_trait;
use anyhow::Result;
use tracing::{info, warn, debug};
use reqwest::Client;
use serde::Deserialize;
use std::sync::Arc;
use std::collections::HashSet;
use once_cell::sync::Lazy;
use regex::Regex;

/// V14.6: Identifies high-value administrative subdomains for priority auth scanning
static ADMIN_SUBDOMAIN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)^(admin|internal|vpn|auth|sso|idp|staff|portal|dev|backend|manage|mgmt)\.")
        .expect("Valid admin subdomain regex")
});

// V5 FIX (Stealth): Removed LivenessChecker and Jitter from OsintScanner.
// A passive OSINT phase should never touch the target's infrastructure directly.
pub struct OsintScanner {
    proxy_manager: Arc<crate::utils::proxy::ProxyManager>,
}

#[derive(Deserialize, Debug)]
struct CrtShEntry {
    name_value: String,
}

impl OsintScanner {
    pub fn new(pm: Arc<crate::utils::proxy::ProxyManager>) -> Self {
        Self { proxy_manager: pm }
    }

    async fn get_client(&self, host: &str) -> Result<Client> {
        let (_, client) = self.proxy_manager.get_client_fail_closed(host)?;
        Ok(client)
    }

    async fn query_crt_sh(&self, domain: &str) -> Result<HashSet<String>> {
        let url = format!("https://crt.sh/?q=%.{}&output=json", domain);
        debug!("Querying crt.sh for {}", domain);
        
        // crt.sh can be slow/flaky, retry logic recommended but keeping simple for now
        let client = self.get_client("crt.sh").await?;
        let resp = client.get(&url).send().await?;
        
        if !resp.status().is_success() {
             warn!("crt.sh returned status: {}", resp.status());
             return Ok(HashSet::new());
        }

        let entries: Vec<CrtShEntry> = resp.json().await?;
        let mut subdomains = HashSet::new();
        
        for entry in entries {
            for line in entry.name_value.split('\n') {
                let clean = line.trim().trim_end_matches('.');
                // Filter out wildcards and unrelated domains
                if !clean.contains('*') && clean.ends_with(domain) {
                    subdomains.insert(clean.to_string());
                }
            }
        }
        
        Ok(subdomains)
    }

    async fn query_shodan(&self, domain: &str) -> Result<HashSet<String>> {
        let api_key = match std::env::var("SHODAN_API_KEY") {
            Ok(key) if !key.trim().is_empty() => key,
            _ => {
                debug!("SHODAN_API_KEY not set. Skipping Shodan OSINT.");
                return Ok(HashSet::new());
            }
        };

        let url = format!("https://api.shodan.io/dns/domain/{}?key={}", domain, api_key);
        debug!("Querying Shodan for {} with key redacted", domain);

        let client = self.get_client("api.shodan.io").await?;
        let resp = client.get(&url).send().await?;
        
        if !resp.status().is_success() {
             warn!("Shodan returned status: {}", resp.status());
             return Ok(HashSet::new());
        }

        #[derive(Deserialize)]
        struct ShodanResponse {
            subdomains: Option<Vec<String>>,
        }

        let result: ShodanResponse = resp.json().await?;
        let mut subdomains = HashSet::new();

        if let Some(subs) = result.subdomains {
            for sub in subs {
                let clean = format!("{}.{}", sub.trim(), domain);
                subdomains.insert(clean);
            }
        }
        
        Ok(subdomains)
    }
}

#[async_trait]
impl DiscoveryPlugin for OsintScanner {
    fn name(&self) -> &'static str {
        "OsintScanner"
    }

        fn metadata(&self) -> crate::plugins::PluginMetadata {
        crate::plugins::PluginMetadata {
            name: self.name().to_string(),
            description: "Passive subdomain discovery using crt.sh and Shodan APIs.".to_string(),
            target_type: crate::plugins::TargetType::Osint,
            risk_level: crate::plugins::RiskLevel::Safe,
            layer: crate::core::capability_layer::ScanLayer::Passive,
            expected_duration: std::time::Duration::from_secs(300),
            capabilities: self.capabilities(),
            cost: 5,
            category: "Reconnaissance".to_string(),
            mitre_attacks: vec![],
            exploit_difficulty: crate::plugins::RiskLevel::Medium,
            blackarch_category: None,
            is_destructive: false,
            poc_mode: false, ..Default::default() }
    }
    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::VulnerabilityScanning]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability("osint").await)
    }


    async fn discover(&self, target: &TargetHost) -> Result<Vec<DiscoveryResult>> {
        info!("OsintScanner: enumerating subdomains for {}", target.host);
        
        let (crt_res, shodan_res) = tokio::join!(
            self.query_crt_sh(&target.host),
            self.query_shodan(&target.host)
        );

        let mut subdomains = HashSet::new();
        
        match crt_res {
            Ok(s) => subdomains.extend(s),
            Err(e) => warn!("Failed to query crt.sh: {}", e),
        }
        
        match shodan_res {
            Ok(s) => subdomains.extend(s),
            Err(e) => warn!("Failed to query Shodan: {}", e),
        }

        if subdomains.is_empty() {
            info!("No subdomains found via passive recon.");
            return Ok(Vec::new());
        }

        info!("OsintScanner: Found {} potential subdomains for {}", subdomains.len(), target.host);
        Ok(subdomains.into_iter().map(|s| {
            let is_hvt = ADMIN_SUBDOMAIN_RE.is_match(&s);
            DiscoveryResult {
                host: s,
                metadata: serde_json::json!({
                    "high_value_target": is_hvt,
                    "priority_plugins": if is_hvt { serde_json::json!(["auth_state_machine"]) } else { serde_json::json!([]) },
                    "source": "crt.sh"
                }),
            }
        }).collect())
    }
}
