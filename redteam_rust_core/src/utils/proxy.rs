use reqwest::{Client, Proxy};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use dashmap::DashMap;
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use tracing::{warn, error, info};
use anyhow::{Result, Context};
use std::collections::VecDeque;
use rand::seq::SliceRandom;

const MAX_LATENCY_SAMPLES: usize = 10;
const DEFAULT_BLACKLIST_DURATION: u64 = 300;

pub struct ProxyManager {
    proxies: Vec<String>,
    clients: Arc<DashMap<String, Client>>,
    blacklist: Arc<DashMap<String, u64>>,
    latency_stats: Arc<DashMap<String, VecDeque<u64>>>,
    blacklist_duration_sec: u64,
    insecure: bool,
}

impl ProxyManager {
    pub fn new(proxies: Vec<String>, insecure: bool) -> Self {
        let pm = Self {
            proxies,
            clients: Arc::new(DashMap::new()),
            blacklist: Arc::new(DashMap::new()),
            latency_stats: Arc::new(DashMap::new()),
            blacklist_duration_sec: DEFAULT_BLACKLIST_DURATION,
            insecure,
        };

        // Start background health checker if there are proxies
        if !pm.proxies.is_empty() {
             pm.start_health_checker();
        }

        pm
    }

    fn start_health_checker(&self) {
        let blacklist = self.blacklist.clone();
        let duration = self.blacklist_duration_sec;
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
                
                let mut to_remove = Vec::new();
                for entry in blacklist.iter() {
                    if now - *entry.value() >= duration {
                        to_remove.push(entry.key().clone());
                    }
                }
                
                for key in to_remove {
                    blacklist.remove(&key);
                    info!("Proxy {} recovered from blacklist via background health checker", key);
                }
            }
        });
    }

    /// Internal method to lazily build a reqwest::Client for a specific proxy
    fn build_client(&self, proxy_str: &str) -> Result<Client> {
        let proxy = Proxy::all(proxy_str).context("Invalid proxy URL")?;
        
        let client = reqwest::Client::builder()
            .proxy(proxy)
            .danger_accept_invalid_certs(self.insecure)
            .timeout(Duration::from_secs(15))
            .build()
            .context("Failed to build reqwest client for proxy")?;
            
        Ok(client)
    }

    /// Build a host-pinned client for a specific proxy
    fn build_client_pinned(&self, proxy_str: &str, host: &str, ip: IpAddr, port: u16) -> Result<Client> {
        let proxy = Proxy::all(proxy_str).context("Invalid proxy URL")?;
        
        let client = reqwest::Client::builder()
            .proxy(proxy)
            .resolve(host, SocketAddr::new(ip, port))
            .danger_accept_invalid_certs(self.insecure)
            .timeout(Duration::from_secs(15))
            .build()
            .context("Failed to build host-pinned reqwest client for proxy")?;
            
        Ok(client)
    }

    /// Report latency for a proxy to improve selection intelligence
    pub fn report_latency(&self, proxy: &str, duration_ms: u64) {
        let mut stats = self.latency_stats.entry(proxy.to_string()).or_insert_with(VecDeque::new);
        stats.push_back(duration_ms);
        if stats.len() > MAX_LATENCY_SAMPLES {
            stats.pop_front();
        }
    }

    fn get_average_latency(&self, proxy: &str) -> u64 {
        if let Some(stats) = self.latency_stats.get(proxy) {
            if stats.is_empty() { return 1000; } // Default high-ish starting point
            let sum: u64 = stats.iter().sum();
            sum / stats.len() as u64
        } else {
            1000 // Unknown proxies start here
        }
    }

    /// Selection intelligence: finds the best available proxy based on latency
    /// but keeps a small chance of picking a random one to discover improvements.
    fn pick_best_proxy(&self) -> Option<String> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        
        let available_proxies: Vec<String> = self.proxies.iter()
            .filter(|p| {
                if let Some(ts) = self.blacklist.get(*p) {
                    if now - *ts < self.blacklist_duration_sec {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect();

        if available_proxies.is_empty() { return None; }

        // 10% chance to pick purely random for discovery
        let mut rng = rand::thread_rng();
        if rand::Rng::gen_bool(&mut rng, 0.1) {
             return available_proxies.choose(&mut rng).cloned();
        }

        // Otherwise, pick the one with lowest average latency
        available_proxies.into_iter()
            .min_by_key(|p| self.get_average_latency(p))
    }

    pub fn get_client(&self) -> Option<(String, Client)> {
        if self.proxies.is_empty() { return None; }

        let p_url = self.pick_best_proxy()?;
        
        use dashmap::mapref::entry::Entry;
        match self.clients.entry(p_url.clone()) {
            Entry::Occupied(oe) => {
                Some((p_url, oe.get().clone()))
            }
            Entry::Vacant(ve) => {
                match self.build_client(&p_url) {
                    Ok(client) => {
                        ve.insert(client.clone());
                        Some((p_url, client))
                    }
                    Err(e) => {
                        error!("Failed to initialize proxy {}: {}", p_url, e);
                        self.blacklist_proxy(&p_url);
                        None
                    }
                }
            }
        }
    }

    pub fn get_client_pinned(&self, host: &str, ip: IpAddr, port: u16) -> Option<(String, Client)> {
        if self.proxies.is_empty() { return None; }

        let p_url = self.pick_best_proxy()?;
        let cache_key = format!("{}:{}:{}:{}", p_url, host, ip, port);
        
        use dashmap::mapref::entry::Entry;
        match self.clients.entry(cache_key) {
            Entry::Occupied(oe) => {
                Some((p_url, oe.get().clone()))
            }
            Entry::Vacant(ve) => {
                match self.build_client_pinned(&p_url, host, ip, port) {
                    Ok(client) => {
                        ve.insert(client.clone());
                        Some((p_url, client))
                    }
                    Err(e) => {
                        error!("Failed to initialize pinned proxy {}: {}", p_url, e);
                        self.blacklist_proxy(&p_url);
                        None
                    }
                }
            }
        }
    }

    pub fn blacklist_proxy(&self, proxy: &str) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        self.blacklist.insert(proxy.to_string(), now);
        warn!("Proxy temporarily blacklisted (timeout, 429, or 503): {}", proxy);
        
        // Penalize latency stats on blacklist
        let mut stats = self.latency_stats.entry(proxy.to_string()).or_insert_with(VecDeque::new);
        stats.push_back(10000); // Massive penalty (10s)
        if stats.len() > MAX_LATENCY_SAMPLES {
            stats.pop_front();
        }
    }

    pub fn is_empty(&self) -> bool {
        self.proxies.is_empty()
    }
}

// Tests
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_proxy_manager_latency_prioritization() {
        let p1 = "http://127.0.0.1:8080".to_string();
        let p2 = "http://127.0.0.1:8081".to_string();
        let pm = ProxyManager::new(vec![p1.clone(), p2.clone()], true);

        // Report p1 as very fast, p2 as slow
        for _ in 0..5 {
            pm.report_latency(&p1, 50);
            pm.report_latency(&p2, 2000);
        }

        // Most calls should favor p1 (due to 10% random chance, we call it multiple times to be sure)
        let mut p1_hits = 0;
        for _ in 0..100 {
            if let Some((url, _)) = pm.get_client() {
                if url == p1 { p1_hits += 1; }
            }
        }
        
        assert!(p1_hits > 80, "Proxy manager did not favor low latency proxy. p1 hits: {}", p1_hits);
    }

    #[tokio::test]
    async fn test_proxy_blacklist_recovery() {
        let proxies = vec!["http://127.0.0.1:8080".to_string()];
        let mut pm = ProxyManager::new(proxies, false);
        pm.blacklist_duration_sec = 1; // 1 second for test
        
        pm.blacklist_proxy("http://127.0.0.1:8080");
        assert!(pm.get_client().is_none());
        
        tokio::time::sleep(Duration::from_secs(2)).await;
        
        // Should recover
        assert!(pm.get_client().is_some());
    }

    #[tokio::test]
    async fn test_proxy_manager_concurrency() {
        let proxies = vec!["http://127.0.0.1:8080".to_string(), "http://127.0.0.1:8081".to_string()];
        let pm = Arc::new(ProxyManager::new(proxies, true));
        
        let mut handles = vec![];
        for _ in 0..20 {
            let pm_clone = pm.clone();
            handles.push(tokio::spawn(async move {
                let _ = pm_clone.get_client();
            }));
        }
        
        for h in handles {
            let _ = h.await;
        }
    }
}
