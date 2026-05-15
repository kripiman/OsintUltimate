use std::sync::{Arc, Mutex};
use std::collections::VecDeque;
use dashmap::DashMap;
use moka::sync::Cache;
use tracing::warn;
use crate::utils::config::ProxyMode;
use super::types::ManagedExit;

pub const MAX_LATENCY_SAMPLES: usize = 10;

pub struct ProxyManager {
    pub(crate) proxies: Arc<Mutex<Vec<String>>>,
    pub(crate) clients: Cache<String, reqwest::Client>,
    pub(crate) latency_stats: Cache<String, VecDeque<u64>>,
    pub(crate) insecure: bool,
    pub(crate) user_agents: Vec<String>,
    pub(crate) identity_cache: Cache<String, String>,
    pub(crate) managed_exits: Arc<DashMap<String, ManagedExit>>,
    pub proxy_mode: ProxyMode,
    pub proxy_pool_size: u32,
    pub(crate) health_checker_handle: Option<tokio::task::AbortHandle>,
    pub egress_killed: Arc<std::sync::atomic::AtomicBool>,
    pub(crate) tls_fingerprint_cache: Cache<String, String>,
}

impl ProxyManager {
    pub fn new(proxies: Vec<String>, insecure: bool, proxy_mode: ProxyMode, proxy_pool_size: u32) -> Self {
        let user_agents = vec![
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36".to_string(),
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36".to_string(),
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36".to_string(),
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0".to_string(),
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.3; rv:123.0) Gecko/20100101 Firefox/123.0".to_string(),
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0".to_string(),
        ];

        let mut pm = Self {
            proxies: Arc::new(Mutex::new(proxies)),
            clients: Cache::builder()
                .max_capacity((proxy_pool_size as u64 * 2).max(50))
                .time_to_idle(std::time::Duration::from_secs(3600))
                .build(),
            latency_stats: Cache::builder()
                .max_capacity(1000)
                .time_to_idle(std::time::Duration::from_secs(3600))
                .build(),
            insecure,
            user_agents,
            identity_cache: Cache::builder()
                .max_capacity(2000)
                .time_to_idle(std::time::Duration::from_secs(3600))
                .build(),
            managed_exits: Arc::new(DashMap::new()),
            proxy_mode,
            proxy_pool_size,
            health_checker_handle: None,
            egress_killed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            tls_fingerprint_cache: Cache::builder()
                .max_capacity(1000)
                .time_to_idle(std::time::Duration::from_secs(3600))
                .build(),
        };

        if !pm.lock_proxies().is_empty() {
             pm.start_health_checker();
        }

        pm
    }

    pub(crate) fn lock_proxies(&self) -> std::sync::MutexGuard<'_, Vec<String>> {
        match self.proxies.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("Proxy Mutex is poisoned, recovering inner data.");
                poisoned.into_inner()
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        self.lock_proxies().is_empty() && self.managed_exits.is_empty()
    }

    pub(crate) fn pick_user_agent(&self) -> String {
        use rand::seq::SliceRandom;
        let mut rng = rand::thread_rng();
        self.user_agents.choose(&mut rng).cloned().unwrap_or_else(|| "Mozilla/5.0".to_string())
    }

    pub fn report_latency(&self, proxy: &str, duration_ms: u64) {
        let mut stats = self.latency_stats.get(proxy).unwrap_or_default();
        stats.push_back(duration_ms);
        if stats.len() > MAX_LATENCY_SAMPLES {
            stats.pop_front();
        }
        self.latency_stats.insert(proxy.to_string(), stats);
    }

    pub(crate) fn get_average_latency(&self, proxy: &str) -> u64 {
        if let Some(stats) = self.latency_stats.get(proxy) {
            if stats.is_empty() { return 1000; }
            let sum: u64 = stats.iter().sum();
            sum / stats.len() as u64
        } else {
            1000
        }
    }

    pub(crate) fn pick_best_proxy(&self) -> Option<String> {
        use rand::seq::SliceRandom;
        let mut candidates: Vec<String> = {
            let proxies_lock = self.lock_proxies();
            proxies_lock.iter()
                .cloned()
                .collect()
        };

        for entry in self.managed_exits.iter() {
            let ip = entry.key();
            let exit = entry.value();
            
            let proxy_url = if let Some(local_port) = exit.local_port {
                format!("socks5h://127.0.0.1:{}", local_port)
            } else if let (Some(u), Some(p)) = (&exit.user, &exit.pass) {
                format!("socks5h://{}:{}@{}:1080", u, p, ip)
            } else {
                format!("socks5h://{}:1080", ip)
            };
            candidates.push(proxy_url);
        }

        if candidates.is_empty() { return None; }

        let mut rng = rand::thread_rng();
        if rand::Rng::gen_bool(&mut rng, 0.1) {
             return candidates.choose(&mut rng).cloned();
        }

        candidates.into_iter()
            .min_by_key(|p| self.get_average_latency(p))
    }

    pub fn get_best_socks_url(&self) -> Option<String> {
        use rand::seq::SliceRandom;
        let managed: Vec<String> = self.managed_exits.iter()
            .map(|e| e.key().clone())
            .collect();
            
        if !managed.is_empty() {
             let mut rng = rand::thread_rng();
             let ip = managed.choose(&mut rng)?;
             
             if let Some(exit) = self.managed_exits.get(ip) {
                 if let Some(local_port) = exit.local_port {
                     return Some(format!("socks5h://127.0.0.1:{}", local_port));
                 }
                 if let (Some(u), Some(p)) = (&exit.user, &exit.pass) {
                     return Some(format!("socks5h://{}:{}@{}:1080", u, p, ip));
                 }
             }
             return Some(format!("socks5h://{}:1080", ip));
        }
        
        let best = self.pick_best_proxy()?;
        if best.starts_with("socks") {
            Some(best)
        } else {
            None
        }
    }

    pub async fn wait_for_readiness(&self, timeout: std::time::Duration) -> anyhow::Result<()> {
        let start = std::time::Instant::now();
        let check_url = std::env::var("INTERACTSH_SERVER_URL")
            .unwrap_or_else(|_| "http://1.1.1.1".to_string());
        
        tracing::info!("⏳ STEALTH: Waiting for Egress Readiness Gate (Checking vs {})...", check_url);
        
        while start.elapsed() < timeout {
            if !self.is_empty() {
                if let Some((_url, client)) = self.get_client("readiness-check.com") {
                    match tokio::time::timeout(std::time::Duration::from_secs(5), client.head(&check_url).send()).await {
                        Ok(Ok(resp)) if resp.status().is_success() || resp.status().is_redirection() => {
                            tracing::info!("🛡️ STEALTH: Egress readiness verified via functional proxy. {} nodes available.", 
                                self.lock_proxies().len() + self.managed_exits.len());
                            return Ok(());
                        }
                        Ok(Ok(resp)) => {
                            warn!("⚠️ STEALTH: Proxy responded but check failed (Status: {}). Retrying...", resp.status());
                        }
                        _ => {
                            warn!("⚠️ STEALTH: Selected proxy failed connectivity check. Blacklisting and retrying...");
                        }
                    }
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        }
        
        anyhow::bail!("V15.5 OPSEC Critical: Timeout exceeded waiting for functional egress. Aborting mission.")
    }

    pub fn get_human_delay(&self) -> std::time::Duration {
        use rand_distr::{Distribution, LogNormal};
        let mut rng = rand::thread_rng();
        let normal = LogNormal::new(1.0, 0.5).unwrap();
        let sample = normal.sample(&mut rng);
        std::time::Duration::from_millis((sample * 1000.0) as u64)
    }

    pub fn get_adaptive_delay(&self, proxy: &str) -> std::time::Duration {
        let base_delay = self.get_human_delay();
        let multiplier = if let Some(stats) = self.latency_stats.get(proxy) {
            let avg = if stats.is_empty() { 1000 } else { stats.iter().sum::<u64>() / stats.len() as u64 };
            if avg > 2000 { 1.5 } else { 1.0 }
        } else {
            1.0
        };
        base_delay.mul_f64(multiplier)
    }

    pub fn add_proxy(&self, proxy: String) {
        let mut proxies = self.lock_proxies();
        if !proxies.contains(&proxy) {
            proxies.push(proxy);
        }
    }
}

impl Drop for ProxyManager {
    fn drop(&mut self) {
        if let Some(handle) = self.health_checker_handle.take() {
            handle.abort();
        }
        tracing::info!("ProxyManager: Shutting down.");
    }
}
