use crate::plugins::{DiscoveryPlugin, Capability, PluginMetadata, RiskLevel, TargetType};
use crate::models::{TargetHost, PLUGIN_SOVEREIGN_RECON};
use crate::core::capability_layer::ScanLayer;
use crate::utils::proxy::ProxyManager;
use crate::utils::common::HumanJitter;
use async_trait::async_trait;
use anyhow::Result;
use tracing::{info, warn, debug};
use serde::Deserialize;
use std::sync::{Arc, Mutex};
use std::collections::HashSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use reqwest::Client;

/// Sentinel Credit Manager to ensure daily budget is respected for paid APIs.
struct CreditManager {
    daily_budget: u32,
    used_today: Mutex<u32>,
    last_reset: Mutex<u64>,
}

impl CreditManager {
    fn new(budget: u32) -> Self {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        Self {
            daily_budget: budget,
            used_today: Mutex::new(0),
            last_reset: Mutex::new(now),
        }
    }

    fn can_spend(&self, cost: u32) -> bool {
        let mut used = self.used_today.lock().unwrap();
        let mut last = self.last_reset.lock().unwrap();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();

        // Check if 24h passed
        if now - *last >= 86400 {
            *used = 0;
            *last = now;
            info!("🛡️ SENTINEL: Daily recon budget reset.");
        }

        if *used + cost <= self.daily_budget {
            *used += cost;
            true
        } else {
            warn!("⚠️ SENTINEL: Daily budget reached ({}/{}). Skipping high-cost API call.", *used, self.daily_budget);
            false
        }
    }
}

pub struct SovereignReconScanner {
    proxy_manager: Arc<ProxyManager>,
    jitter: Arc<HumanJitter>,
    credit_manager: Arc<CreditManager>,
    chaos_key: Option<String>,
    netlas_key: Option<String>,
    sectrails_key: Option<String>,
    shodan_key: Option<String>,
    criminalip_key: Option<String>,
}

impl SovereignReconScanner {
    pub fn new(config: &crate::utils::config::Config, pm: Arc<ProxyManager>) -> Self {
        Self {
            proxy_manager: pm,
            jitter: Arc::new(HumanJitter::new(100, 500)), // Default jitter 100-500ms
            credit_manager: Arc::new(CreditManager::new(config.netlas_daily_budget)),
            chaos_key: config.chaos_api_key.clone(),
            netlas_key: config.netlas_api_key.clone(),
            sectrails_key: config.securitytrails_api_key.clone(),
            shodan_key: config.shodan_api_key.clone(),
            criminalip_key: config.criminalip_api_key.clone(),
        }
    }

    async fn get_client(&self, host: &str) -> Result<Client> {
        let (_, client) = self.proxy_manager.get_client_fail_closed(host)?;
        Ok(client)
    }

    // --- Phase 0: Wayback Machine (URL History) ---
    async fn query_wayback(&self, domain: &str) -> HashSet<String> {
        let mut subdomains = HashSet::new();
        debug!("🕰️ Phase 0: Wayback Machine historical URL discovery for {}", domain);
        let url = format!("http://web.archive.org/cdx/search/cdx?url=*.{}/*&output=json&collapse=urlkey&fl=original", domain);
        
        if let Ok(client) = self.get_client("web.archive.org").await {
            if let Ok(resp) = client.get(&url).send().await {
                if let Ok(data) = resp.json::<Vec<Vec<String>>>().await {
                    for entry in data.into_iter().skip(1) { // Skip header
                        if let Some(target_url) = entry.first() {
                            if let Ok(parsed) = url::Url::parse(target_url) {
                                if let Some(host) = parsed.host_str() {
                                    if host.ends_with(domain) {
                                        subdomains.insert(host.to_string());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        subdomains
    }

    // --- Phase 0.5: HackerTarget ---
    async fn query_hackertarget(&self, domain: &str) -> HashSet<String> {
        let mut subdomains = HashSet::new();
        debug!("🎯 Phase 0.5: HackerTarget host search for {}", domain);
        let url = format!("https://api.hackertarget.com/hostsearch/?q={}", domain);
        
        if let Ok(client) = self.get_client("api.hackertarget.com").await {
            if let Ok(resp) = client.get(&url).send().await {
                if let Ok(text) = resp.text().await {
                    for line in text.lines() {
                        let parts: Vec<&str> = line.split(',').collect();
                        if let Some(host) = parts.first() {
                            if host.ends_with(domain) {
                                subdomains.insert(host.to_string());
                            }
                        }
                    }
                }
            }
        }
        subdomains
    }

    // --- Phase 1: Chaos (PD) ---
    async fn query_chaos(&self, domain: &str) -> HashSet<String> {
        let mut subdomains = HashSet::new();
        let key = match &self.chaos_key {
            Some(k) if !k.is_empty() => k,
            _ => return subdomains,
        };

        debug!("🚀 Phase 1: Chaos strike for {}", domain);
        let url = format!("https://chaos.projectdiscovery.io/v1/domains/{}/subdomains", domain);
        
        if let Ok(client) = self.get_client("chaos.projectdiscovery.io").await {
            if let Ok(resp) = client.get(&url).header("Authorization", key).send().await {
                #[derive(Deserialize)]
                struct ChaosResp { subdomains: Option<Vec<String>> }
                if let Ok(data) = resp.json::<ChaosResp>().await {
                    if let Some(subs) = data.subdomains {
                        for s in subs { subdomains.insert(format!("{}.{}", s, domain)); }
                    }
                }
            }
        }
        subdomains
    }

    // --- Phase 2: SecurityTrails ---
    async fn query_securitytrails(&self, domain: &str) -> HashSet<String> {
        let mut subdomains = HashSet::new();
        let key = match &self.sectrails_key {
            Some(k) if !k.is_empty() => k,
            _ => return subdomains,
        };

        debug!("🛰️ Phase 2: SecurityTrails mapping for {}", domain);
        let url = format!("https://api.securitytrails.com/v1/domain/{}/subdomains", domain);
        
        if let Ok(client) = self.get_client("api.securitytrails.com").await {
            if let Ok(resp) = client.get(&url).header("APIKEY", key).send().await {
                #[derive(Deserialize)]
                struct STResp { subdomains: Option<Vec<String>> }
                if let Ok(data) = resp.json::<STResp>().await {
                    if let Some(subs) = data.subdomains {
                        for s in subs { subdomains.insert(format!("{}.{}", s, domain)); }
                    }
                }
            }
        }
        subdomains
    }

    // --- Phase 3: Netlas (Paid & Optimized) ---
    async fn query_netlas(&self, domain: &str) -> HashSet<String> {
        let mut subdomains = HashSet::new();
        let key = match &self.netlas_key {
            Some(k) if !k.is_empty() => k,
            _ => return subdomains,
        };

        // ENFORCE BUDGET
        if !self.credit_manager.can_spend(1) {
            return subdomains;
        }

        debug!("💎 Phase 3: Netlas High-Precision Deep Dive for {}", domain);
        // Using Netlas Responses API to find related domains via certificates/SSL
        let query = format!("domain:*.{}", domain);
        let url = format!("https://app.netlas.io/api/v1/responses/?q={}", urlencoding::encode(&query));
        
        if let Ok(client) = self.get_client("app.netlas.io").await {
            if let Ok(resp) = client.get(&url).header("X-API-Key", key).send().await {
                #[derive(Deserialize)]
                struct NetlasItem { data: Option<NetlasData> }
                #[derive(Deserialize)]
                struct NetlasData { domain: Option<String> }
                #[derive(Deserialize)]
                struct NetlasResp { items: Option<Vec<NetlasItem>> }
                
                if let Ok(data) = resp.json::<NetlasResp>().await {
                    if let Some(items) = data.items {
                        for item in items {
                            if let Some(d) = item.data.and_then(|x| x.domain) {
                                subdomains.insert(d);
                            }
                        }
                    }
                }
            }
        }
        subdomains
    }

    // --- Phase 4: Shodan (Enrichment) ---
    async fn query_shodan(&self, domain: &str) -> HashSet<String> {
        let mut results = HashSet::new();
        let key = match &self.shodan_key {
            Some(k) if !k.is_empty() => k,
            _ => return results,
        };

        debug!(" telescope Phase 4: Shodan infrastructure discovery for {}", domain);
        let url = format!("https://api.shodan.io/dns/domain/{}", domain);
        
        if let Ok(client) = self.get_client("api.shodan.io").await {
            if let Ok(resp) = client.get(&url).header("Authorization", format!("Bearer {}", key)).send().await {
                #[derive(Deserialize)]
                struct ShodanResp { subdomains: Option<Vec<String>> }
                if let Ok(data) = resp.json::<ShodanResp>().await {
                    if let Some(subs) = data.subdomains {
                        for s in subs { results.insert(format!("{}.{}", s, domain)); }
                    }
                }
            }
        }
        results
    }

    // --- Phase 5: Criminal IP (Reputation) ---
    async fn query_criminalip(&self, host: &str) -> Vec<String> {
        let mut findings = Vec::new();
        let key = match &self.criminalip_key {
            Some(k) if !k.is_empty() => k,
            _ => return findings,
        };

        debug!("🏴‍☠️ Phase 5: Criminal IP reputation scoring for {}", host);
        let url = format!("https://api.criminalip.io/v1/asset/search?query={}", urlencoding::encode(host));
        
        if let Ok(client) = self.get_client("api.criminalip.io").await {
            if let Ok(resp) = client.get(&url)
                .header("x-api-key", key)
                .header("User-Agent", "Sentinel/1.0")
                .send().await {
                
                // Generic scoring check
                #[derive(Deserialize)]
                struct CIPResp { score: Option<CIPScore> }
                #[derive(Deserialize)]
                struct CIPScore { inbound: Option<u32>, _outbound: Option<u32> }
                
                if let Ok(data) = resp.json::<CIPResp>().await {
                    if let Some(score) = data.score {
                        if score.inbound.unwrap_or(0) > 3 {
                            findings.push(format!("CRIMINALIP: {} has suspicious inbound reputation score", host));
                        }
                    }
                }
            }
        }
        findings
    }
}

#[async_trait]
impl DiscoveryPlugin for SovereignReconScanner {
    fn name(&self) -> &'static str {
        PLUGIN_SOVEREIGN_RECON
    }

    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: self.name().to_string(),
            description: "Sentinel Sovereign Orchestrator: Multi-phase optimized OSINT pipeline (Chaos -> Netlas -> Shodan).".to_string(),
            target_type: TargetType::Osint,
            risk_level: RiskLevel::Safe,
            layer: ScanLayer::Passive,
            expected_duration: Duration::from_secs(600),
            capabilities: self.capabilities(),
            cost: 10,
            category: "Osint".to_string(),
            ..Default::default()
        }
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![
            Capability::SubdomainEnumeration,
            Capability::HistoricalRecon,
            Capability::OsintDiscovery,
        ]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        Ok(true) // Native plugin, no binaries required
    }

    async fn discover(&self, target: &TargetHost) -> Result<Vec<String>> {
        info!("🔱 SOVEREIGN RECON: Launching optimized pipeline for {}", target.host);
        
        let mut all_results = HashSet::new();

        // Phase 0: Instant Free Aggregates
        info!("🕰️ Phase 0: Wayback & HackerTarget historical lookup...");
        let wayback = self.query_wayback(&target.host).await;
        if !wayback.is_empty() {
            info!("  ✅ Wayback Machine found {} unique subdomains", wayback.len());
            all_results.extend(wayback);
        }
        
        let ht = self.query_hackertarget(&target.host).await;
        if !ht.is_empty() {
            info!("  ✅ HackerTarget found {} unique hosts", ht.len());
            all_results.extend(ht);
        }

        // 1. Chaos (Fast & Free) - STRATEGIC PRIORITY
        info!("🚀 Phase 1/5: Chaos strike (Fast/Free)...");
        let chaos = self.query_chaos(&target.host).await;
        if !chaos.is_empty() {
            info!("  ✅ Chaos captured {} subdomains", chaos.len());
            all_results.extend(chaos);
        } else {
            warn!("  ⚠️ Phase 1: No subdomains found in Chaos.");
        }

        // 2. SecurityTrails
        self.jitter.sleep().await;
        info!("🛰️ Phase 2/5: SecurityTrails mapping...");
        let st = self.query_securitytrails(&target.host).await;
        if !st.is_empty() {
            info!("  ✅ SecurityTrails captured {} subdomains", st.len());
            all_results.extend(st);
        }

        // 3. Netlas (Paid - Precision)
        self.jitter.sleep().await;
        info!("💎 Phase 3/5: Netlas High-Precision Deep Dive...");
        let netlas = self.query_netlas(&target.host).await;
        if !netlas.is_empty() {
            info!("  ✅ Netlas captured {} subdomains", netlas.len());
            all_results.extend(netlas);
        }

        // 4. Shodan
        self.jitter.sleep().await;
        info!("🔭 Phase 4/5: Shodan infrastructure discovery...");
        let shodan = self.query_shodan(&target.host).await;
        if !shodan.is_empty() {
            info!("  ✅ Shodan captured {} subdomains", shodan.len());
            all_results.extend(shodan);
        }

        // 5. Criminal IP (Reputation)
        self.jitter.sleep().await;
        info!("🏴‍☠️ Phase 5/5: Criminal IP reputation scoring...");
        let cip_findings = self.query_criminalip(&target.host).await;
        for finding in cip_findings {
            info!("  ✅ {}", finding);
        }

        // 6. Automatic Fallback: Subfinder (Emergency)
        if all_results.is_empty() {
            warn!("⚠️ SOVEREIGN RECON: All primary phases returned ZERO results. Triggering Subfinder Emergency Fallback...");
            use crate::plugins::reconnaissance::osint::subfinder::SubfinderScanner;
            let subfinder = SubfinderScanner::new(self.proxy_manager.clone());
            if let Ok(subs) = subfinder.discover(target).await {
                info!("  🚑 Subfinder Fallback captured {} subdomains", subs.len());
                all_results.extend(subs);
            }
        }

        let final_list: Vec<String> = all_results.into_iter().collect();
        info!("✅ SOVEREIGN RECON COMPLETE: Captured {} total assets for {}", final_list.len(), target.host);
        
        Ok(final_list)
    }
}
