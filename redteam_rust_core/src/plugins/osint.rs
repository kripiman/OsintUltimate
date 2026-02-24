use crate::plugins::DiscoveryPlugin;
use crate::models::TargetHost;
use async_trait::async_trait;
use anyhow::Result;
use tracing::{info, warn, debug};
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashSet;

// V5 FIX (Stealth): Removed LivenessChecker and Jitter from OsintScanner.
// A passive OSINT phase should never touch the target's infrastructure directly.
pub struct OsintScanner {
    client: Client,
}

#[derive(Deserialize, Debug)]
struct CrtShEntry {
    name_value: String,
}

impl OsintScanner {
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("Failed to build HTTP client for OSINT");
            
        Self { client }
    }

    async fn query_crt_sh(&self, domain: &str) -> Result<HashSet<String>> {
        let url = format!("https://crt.sh/?q=%.{}&output=json", domain);
        debug!("Querying crt.sh for {}", domain);
        
        // crt.sh can be slow/flaky, retry logic recommended but keeping simple for now
        let resp = self.client.get(&url).send().await?;
        
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

        let resp = self.client.get(&url).send().await?;
        
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

    async fn discover(&self, target: &TargetHost) -> Result<Vec<String>> {
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
        Ok(subdomains.into_iter().collect())
    }
}
