use crate::plugins::ScannerPlugin;
use crate::models::{TargetHost, Finding, Severity, Category};
use crate::utils::LivenessChecker; // Import LivenessChecker
use async_trait::async_trait;
use anyhow::Result;
use tracing::{info, warn, debug};
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashSet;
use futures::stream::{self, StreamExt}; // Concurrent stream
use std::sync::Arc; // Shared state

pub struct OsintScanner {
    client: Client,
    liveness: LivenessChecker, // Use shared checker
}

#[derive(Deserialize, Debug)]
struct CrtShEntry {
    name_value: String,
}

impl OsintScanner {
    pub fn new(liveness: LivenessChecker) -> Self {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(20))
            .user_agent("Mozilla/5.0 (compatible; RedTeamRust/1.0)")
            .build()
            .expect("Failed to build OSINT client");
            
        Self { client, liveness }
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
}

#[async_trait]
impl ScannerPlugin for OsintScanner {
    fn name(&self) -> &'static str {
        "OsintScanner"
    }

    async fn scan(&self, target: &mut TargetHost) -> Result<()> {
        info!("OsintScanner: enumerating subdomains for {}", target.host);
        
        // 1. Passive Recon (crt.sh)
        let subdomains = match self.query_crt_sh(&target.host).await {
            Ok(s) => s,
            Err(e) => {
                warn!("Failed to query crt.sh: {}", e);
                return Ok(());
            }
        };

        if subdomains.is_empty() {
            info!("No subdomains found via passive recon.");
            return Ok(());
        }

        info!("Found {} unique subdomains from crt.sh. Verifying...", subdomains.len());
        

        
        let liveness_checker = Arc::new(&self.liveness);
        
        // 2. Concurrent Active Verification (DNS)
        let live_subdomains: Vec<(String, String)> = stream::iter(subdomains)
            .map(|sub| {
                let checker = liveness_checker.clone();
                let target_host = target.host.clone();
                async move {
                    if sub == target_host { return None; }
                    
                    if let Some(ip) = checker.is_live(&sub).await {
                        debug!("Subdomain alive: {} -> {}", sub, ip);
                        Some((sub, ip.to_string()))
                    } else {
                        None
                    }
                }
            })
            .buffer_unordered(50) // Concurrency limit
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .flatten()
            .collect();

        // 3. Report Findings
        for (sub, ip) in live_subdomains {
            target.findings.push(Finding::new(
                "SUBDOMAIN-DISCOVERY",
                Category::Recon,
                Severity::Info,
                &format!("Discovered subdomain: {}", sub),
                serde_json::json!({
                    "subdomain": sub,
                    "ip": ip,
                    "source": "crt.sh + DNS"
                })
            ));
        }

        Ok(())
    }
}
