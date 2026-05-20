mod sources;
use crate::plugins::{DiscoveryPlugin, Capability, PluginMetadata, RiskLevel, TargetType, DiscoveryResult};
use crate::models::{TargetHost, PLUGIN_SOVEREIGN_RECON};
use crate::core::capability_layer::ScanLayer;
use crate::utils::proxy::ProxyManager;
use crate::utils::common::HumanJitter;
use async_trait::async_trait;
use anyhow::Result;
use tracing::{info, warn};
use crate::core::policy::{PolicyProvider, ReloadablePolicy};
use std::sync::Arc;
use std::time::Duration;
use reqwest::Client;
pub struct SovereignReconScanner {
    proxy_manager: Arc<ProxyManager>,
    jitter: Arc<HumanJitter>,
    policy: Arc<dyn PolicyProvider>,
    strict_scope: bool,
    chaos_key: Option<String>,
    netlas_key: Option<String>,
    sectrails_key: Option<String>,
    criminalip_key: Option<String>,
    fofa_email: Option<String>,
    fofa_key: Option<String>,
    zoomeye_key: Option<String>,
    pub shodan_paid_max_hosts: usize,
    pub shodan_host_ip_max_hosts: usize,
    pub fofa_max_hosts: usize,
    pub securitytrails_max_hosts: usize,
}
impl SovereignReconScanner {
    pub fn new(config: &crate::utils::config::Config, pm: Arc<ProxyManager>) -> Self {
        Self {
            proxy_manager: pm,
            jitter: Arc::new(HumanJitter::new(100, 500)), // Default jitter 100-500ms
            policy: Arc::new(ReloadablePolicy::new(config.policy_file.as_deref())),
            strict_scope: config.strict_scope,
            chaos_key: config.chaos_api_key.clone(),
            netlas_key: config.netlas_api_key.clone(),
            sectrails_key: config.securitytrails_api_key.clone(),
            criminalip_key: config.criminalip_api_key.clone(),
            fofa_email: config.fofa_email.clone(),
            fofa_key: config.fofa_api_key.clone(),
            zoomeye_key: config.zoomeye_api_key.clone(),
            shodan_paid_max_hosts: config.shodan_paid_max_hosts_per_scan,
            shodan_host_ip_max_hosts: config.shodan_host_ip_max_hosts_per_scan,
            fofa_max_hosts: config.fofa_max_hosts_per_scan,
            securitytrails_max_hosts: config.securitytrails_max_hosts_per_scan,
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
        
        // Pre-flight scope check
        if self.strict_scope && !self.policy.is_target_allowed(&target.host) {
            warn!("🛡️ V14.2 SCOPE: Target host '{}' is OUT OF SCOPE. Aborting sovereign recon immediately.", target.host);
            return Ok(vec![]);
        }

        let mut all_results: std::collections::HashMap<String, serde_json::Value> = std::collections::HashMap::new();

        // Phase 0: Instant Free Aggregates
        info!("🕰️ Phase 0: Wayback & HackerTarget historical lookup...");
        let wayback = self.query_wayback(&target.host).await;
        if !wayback.is_empty() {
            info!("  ✅ Wayback Machine found {} unique subdomains", wayback.len());
            for s in wayback {
                if !self.strict_scope || self.policy.is_target_allowed(&s) {
                    all_results.insert(s, serde_json::json!({"src": "wayback", "confidence": 0.6}));
                }
            }
        }
        
        let ht = self.query_hackertarget(&target.host).await;
        if !ht.is_empty() {
            info!("  ✅ HackerTarget found {} unique hosts", ht.len());
            for s in ht {
                if !self.strict_scope || self.policy.is_target_allowed(&s) {
                    all_results.insert(s, serde_json::json!({"src": "hackertarget", "confidence": 0.7}));
                }
            }
        }

        // 1. Chaos (Fast & Free) - STRATEGIC PRIORITY
        info!("🚀 Phase 1/7: Chaos strike (Fast/Free)...");
        let chaos = self.query_chaos(&target.host).await;
        if !chaos.is_empty() {
            info!("  ✅ Chaos found {} unique subdomains", chaos.len());
            for s in chaos {
                if !self.strict_scope || self.policy.is_target_allowed(&s) {
                    all_results.insert(s, serde_json::json!({"src": "chaos", "confidence": 0.9}));
                }
            }
        } else {
            warn!("  ⚠️ Phase 1: No subdomains found in Chaos.");
        }

        // Phase 2-7: Build unique set of in-scope hosts accumulated so far
        let mut in_scope_hosts: Vec<String> = all_results.keys().cloned().collect();
        if !in_scope_hosts.contains(&target.host) {
            in_scope_hosts.push(target.host.clone());
        }

        info!("🛡️ V14.2 SCOPE: Running budget Phases 2-7 for {} in-scope hosts...", in_scope_hosts.len());

        for host in in_scope_hosts {
            // 2. SecurityTrails
            self.jitter.sleep().await;
            info!("🛰️ Phase 2/7: SecurityTrails mapping for {}...", host);
            let st = self.query_securitytrails(&host).await;
            if !st.is_empty() {
                info!("  ✅ SecurityTrails captured {} subdomains", st.len());
                for s in st {
                    if !self.strict_scope || self.policy.is_target_allowed(&s) {
                        all_results.insert(s, serde_json::json!({"src": "securitytrails", "confidence": 0.8}));
                    }
                }
            }

            // 3. Netlas (Paid - Precision)
            self.jitter.sleep().await;
            info!("💎 Phase 3/7: Netlas High-Precision Deep Dive for {}...", host);
            let netlas = self.query_netlas(&host).await;
            if !netlas.is_empty() {
                info!("  ✅ Netlas captured {} subdomains", netlas.len());
                for s in netlas {
                    if !self.strict_scope || self.policy.is_target_allowed(&s) {
                        all_results.insert(s, serde_json::json!({"src": "netlas", "confidence": 0.9}));
                    }
                }
            }

            // 4. Shodan
            self.jitter.sleep().await;
            info!("🔭 Phase 4/7: Shodan infrastructure discovery for {}...", host);
            let shodan = self.query_shodan(&host).await;
            if !shodan.is_empty() {
                info!("  ✅ Shodan captured {} subdomains", shodan.len());
                for s in shodan {
                    if !self.strict_scope || self.policy.is_target_allowed(&s) {
                        all_results.insert(s, serde_json::json!({"src": "shodan", "confidence": 0.85}));
                    }
                }
            }

            // 5. Criminal IP (Reputation)
            self.jitter.sleep().await;
            info!("🏴‍☠️ Phase 5/7: Criminal IP reputation scoring for {}...", host);
            let cip_findings = self.query_criminalip(&host).await;
            for finding in cip_findings {
                info!("  ✅ {}", finding);
                if let Some(meta) = all_results.get_mut(&host) {
                    if let Some(obj) = meta.as_object_mut() {
                        obj.insert("criminalip_alert".to_string(), serde_json::json!(finding));
                    }
                }
            }

            // 6. FOFA (Global Coverage)
            self.jitter.sleep().await;
            info!("🌍 Phase 6/7: FOFA Global Asset Discovery for {}...", host);
            let fofa = self.query_fofa(&host).await;
            if !fofa.is_empty() {
                info!("  ✅ FOFA captured {} assets", fofa.len());
                for s in fofa {
                    if !self.strict_scope || self.policy.is_target_allowed(&s) {
                        all_results.insert(s, serde_json::json!({"src": "fofa", "confidence": 0.7}));
                    }
                }
            }

            // 7. ZoomEye (Network Context)
            self.jitter.sleep().await;
            info!("👁️ Phase 7/7: ZoomEye Network Context for {}...", host);
            let zoomeye = self.query_zoomeye(&host).await;
            if !zoomeye.is_empty() {
                info!("  ✅ ZoomEye captured {} assets", zoomeye.len());
                for s in zoomeye {
                    if !self.strict_scope || self.policy.is_target_allowed(&s) {
                        all_results.insert(s, serde_json::json!({"src": "zoomeye", "confidence": 0.75}));
                    }
                }
            }
        }

        // 6. Automatic Fallback: Subfinder (Emergency)
        if all_results.is_empty() {
            warn!("⚠️ SOVEREIGN RECON: All primary phases returned ZERO results. Triggering Subfinder Emergency Fallback...");
            use crate::plugins::reconnaissance::osint::subfinder::SubfinderScanner;
            let subfinder = SubfinderScanner::new(self.proxy_manager.clone());
            if let Ok(subs) = subfinder.discover(target).await {
                info!("  🚑 Subfinder Fallback captured {} subdomains", subs.len());
                for r in subs {
                    if !self.strict_scope || self.policy.is_target_allowed(&r.host) {
                        all_results.insert(r.host, serde_json::json!({"src": "subfinder", "confidence": 0.85}));
                    }
                }
            }
        }

        let final_list: Vec<DiscoveryResult> = all_results.into_iter()
            .map(|(host, metadata)| DiscoveryResult { host, metadata })
            .collect();
        info!("✅ SOVEREIGN RECON COMPLETE: Captured {} total assets for {}", final_list.len(), target.host);
        
        Ok(final_list)
    }
}
