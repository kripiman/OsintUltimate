mod credit;
mod sources;
use crate::plugins::{DiscoveryPlugin, Capability, PluginMetadata, RiskLevel, TargetType, DiscoveryResult};
use crate::models::{TargetHost, PLUGIN_SOVEREIGN_RECON};
use crate::core::capability_layer::ScanLayer;
use crate::utils::proxy::ProxyManager;
use crate::utils::common::HumanJitter;
use async_trait::async_trait;
use anyhow::Result;
use tracing::{info, warn};
use std::sync::Arc;
use std::time::Duration;
use reqwest::Client;
use credit::CreditManager;
pub struct SovereignReconScanner {
    proxy_manager: Arc<ProxyManager>,
    jitter: Arc<HumanJitter>,
    credit_manager: Arc<CreditManager>,
    chaos_key: Option<String>,
    netlas_key: Option<String>,
    sectrails_key: Option<String>,
    shodan_key: Option<String>,
    criminalip_key: Option<String>,
    fofa_email: Option<String>,
    fofa_key: Option<String>,
    zoomeye_key: Option<String>,
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
            fofa_email: config.fofa_email.clone(),
            fofa_key: config.fofa_api_key.clone(),
            zoomeye_key: config.zoomeye_api_key.clone(),
        }
    }
    pub(super) async fn get_client(&self, host: &str) -> Result<Client> {
        let (_, client) = self.proxy_manager.get_client_fail_closed(host)?;
        Ok(client)
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
            description: "Sentinel Sovereign Orchestrator: Multi-phase optimized OSINT pipeline (Chaos -> Netlas -> Shodan -> FOFA -> ZoomEye).".to_string(),
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

    async fn discover(&self, target: &TargetHost) -> Result<Vec<DiscoveryResult>> {
        info!("🔱 SOVEREIGN RECON: Launching optimized pipeline for {}", target.host);
        
        let mut all_results: std::collections::HashMap<String, serde_json::Value> = std::collections::HashMap::new();

        // Phase 0: Instant Free Aggregates
        info!("🕰️ Phase 0: Wayback & HackerTarget historical lookup...");
        let wayback = self.query_wayback(&target.host).await;
        if !wayback.is_empty() {
            info!("  ✅ Wayback Machine found {} unique subdomains", wayback.len());
            for s in wayback { all_results.insert(s, serde_json::json!({})); }
        }
        
        let ht = self.query_hackertarget(&target.host).await;
        if !ht.is_empty() {
            info!("  ✅ HackerTarget found {} unique hosts", ht.len());
            for s in ht { all_results.insert(s, serde_json::json!({})); }
        }

        // 1. Chaos (Fast & Free) - STRATEGIC PRIORITY
        info!("🚀 Phase 1/7: Chaos strike (Fast/Free)...");
        let chaos = self.query_chaos(&target.host).await;
        if !chaos.is_empty() {
            info!("  ✅ Chaos found {} unique subdomains", chaos.len());
            for s in chaos { all_results.insert(s, serde_json::json!({})); }
        } else {
            warn!("  ⚠️ Phase 1: No subdomains found in Chaos.");
        }

        // 2. SecurityTrails
        self.jitter.sleep().await;
        info!("🛰️ Phase 2/7: SecurityTrails mapping...");
        let st = self.query_securitytrails(&target.host).await;
        if !st.is_empty() {
            info!("  ✅ SecurityTrails captured {} subdomains", st.len());
            for s in st { all_results.insert(s, serde_json::json!({})); }
        }

        // 3. Netlas (Paid - Precision)
        self.jitter.sleep().await;
        info!("💎 Phase 3/7: Netlas High-Precision Deep Dive...");
        let netlas = self.query_netlas(&target.host).await;
        if !netlas.is_empty() {
            info!("  ✅ Netlas captured {} subdomains", netlas.len());
            for s in netlas { all_results.insert(s, serde_json::json!({})); }
        }

        // 4. Shodan
        self.jitter.sleep().await;
        info!("🔭 Phase 4/7: Shodan infrastructure discovery...");
        let shodan = self.query_shodan(&target.host).await;
        if !shodan.is_empty() {
            info!("  ✅ Shodan captured {} subdomains", shodan.len());
            for s in shodan { all_results.insert(s, serde_json::json!({})); }
        }

        // 5. Criminal IP (Reputation)
        self.jitter.sleep().await;
        info!("🏴‍☠️ Phase 5/7: Criminal IP reputation scoring...");
        let cip_findings = self.query_criminalip(&target.host).await;
        for finding in cip_findings {
            info!("  ✅ {}", finding);
        }

        // 6. FOFA (Global Coverage)
        self.jitter.sleep().await;
        info!("🌍 Phase 6/7: FOFA Global Asset Discovery...");
        let fofa = self.query_fofa(&target.host).await;
        if !fofa.is_empty() {
            info!("  ✅ FOFA captured {} assets", fofa.len());
            for s in fofa { all_results.insert(s, serde_json::json!({})); }
        }

        // 7. ZoomEye (Network Context)
        self.jitter.sleep().await;
        info!("👁️ Phase 7/7: ZoomEye Network Context...");
        let zoomeye = self.query_zoomeye(&target.host).await;
        if !zoomeye.is_empty() {
            info!("  ✅ ZoomEye captured {} assets", zoomeye.len());
            for s in zoomeye { all_results.insert(s, serde_json::json!({})); }
        }

        // 6. Automatic Fallback: Subfinder (Emergency)
        if all_results.is_empty() {
            warn!("⚠️ SOVEREIGN RECON: All primary phases returned ZERO results. Triggering Subfinder Emergency Fallback...");
            use crate::plugins::reconnaissance::osint::subfinder::SubfinderScanner;
            let subfinder = SubfinderScanner::new(self.proxy_manager.clone());
            if let Ok(subs) = subfinder.discover(target).await {
                info!("  🚑 Subfinder Fallback captured {} subdomains", subs.len());
                for r in subs { all_results.insert(r.host, r.metadata); }
            }
        }

        let final_list: Vec<DiscoveryResult> = all_results.into_iter()
            .map(|(host, metadata)| DiscoveryResult { host, metadata })
            .collect();
        info!("✅ SOVEREIGN RECON COMPLETE: Captured {} total assets for {}", final_list.len(), target.host);
        
        Ok(final_list)
    }
}
