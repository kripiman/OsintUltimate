use reqwest::{Client, Proxy, header::HeaderValue};
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

use std::sync::Mutex;

pub struct ProxyManager {
    proxies: Arc<Mutex<Vec<String>>>,
    clients: Arc<DashMap<String, Client>>,
    blacklist: Arc<DashMap<String, u64>>,
    latency_stats: Arc<DashMap<String, VecDeque<u64>>>,
    blacklist_duration_sec: u64,
    insecure: bool,
    // Pool of modern browser User-Agents for rotation
    user_agents: Vec<String>,
    // RT-Identity: Map host -> User-Agent to maintain consistent identity
    identity_cache: Arc<DashMap<String, String>>,
    // QA-007 FIX: Store handle to abort the health checker task on drop
    _health_checker_handle: Option<tokio::task::AbortHandle>,
    // Managed Exits (V13): IP addresses of DigitalOcean VPS nodes
    managed_exits: Arc<DashMap<String, SystemTime>>,
}

impl ProxyManager {
    pub fn new(proxies: Vec<String>, insecure: bool) -> Self {
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
            clients: Arc::new(DashMap::new()),
            blacklist: Arc::new(DashMap::new()),
            latency_stats: Arc::new(DashMap::new()),
            blacklist_duration_sec: DEFAULT_BLACKLIST_DURATION,
            insecure,
            user_agents,
            identity_cache: Arc::new(DashMap::new()),
            _health_checker_handle: None,
            managed_exits: Arc::new(DashMap::new()),
        };

        // Start background health checker if there can be proxies
        if !pm.lock_proxies().is_empty() {
             pm.start_health_checker();
        }

        pm
    }

    /// Robustness Fix (AUDIT-003): Handle poisoned mutexes without panicking
    fn lock_proxies(&self) -> std::sync::MutexGuard<'_, Vec<String>> {
        match self.proxies.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("Proxy Mutex is poisoned, recovering inner data.");
                poisoned.into_inner()
            }
        }
    }

    fn start_health_checker(&mut self) {
        let blacklist = self.blacklist.clone();
        let duration = self.blacklist_duration_sec;
        
        // QA-007 FIX: Store AbortHandle so the task is cancelled when ProxyManager is dropped
        let handle = tokio::spawn(async move {
            loop {
                let sleep_secs = {
                    let mut rng = rand::thread_rng();
                    rand::Rng::gen_range(&mut rng, 45..120)
                };
                tokio::time::sleep(Duration::from_secs(sleep_secs)).await;

                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
                
                let to_remove: Vec<String> = {
                    let mut keys = Vec::new();
                    for entry in blacklist.iter() {
                        if now - *entry.value() >= duration {
                            keys.push(entry.key().clone());
                        }
                    }
                    keys
                };
                
                for key in to_remove {
                    blacklist.remove(&key);
                    info!("Proxy {} recovered from blacklist (jittered health check)", key);
                }
            }
        });
        self._health_checker_handle = Some(handle.abort_handle());
}

    /// Internal method to lazily build a reqwest::Client for a specific proxy
    fn build_client(&self, proxy_str: &str, user_agent: String) -> Result<Client> {
        let proxy = Proxy::all(proxy_str).context("Invalid proxy URL")?;
        
        let client = reqwest::Client::builder()
            .proxy(proxy)
            .user_agent(user_agent)
            .default_headers({
                let mut h = reqwest::header::HeaderMap::new();
                h.insert("Accept", HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"));
                h.insert("Accept-Language", HeaderValue::from_static("en-US,en;q=0.9"));
                h.insert("Sec-Ch-Ua", HeaderValue::from_static("\"Not A(Brand\";v=\"99\", \"Google Chrome\";v=\"122\", \"Chromium\";v=\"122\""));
                h.insert("Sec-Ch-Ua-Mobile", HeaderValue::from_static("?0"));
                h.insert("Sec-Ch-Ua-Platform", HeaderValue::from_static("\"Windows\""));
                h.insert("Sec-Fetch-Dest", HeaderValue::from_static("document"));
                h.insert("Sec-Fetch-Mode", HeaderValue::from_static("navigate"));
                h.insert("Sec-Fetch-Site", HeaderValue::from_static("none"));
                h.insert("Sec-Fetch-User", HeaderValue::from_static("?1"));
                h.insert("Upgrade-Insecure-Requests", HeaderValue::from_static("1"));
                h
            })
            .danger_accept_invalid_certs(self.insecure)
            .timeout(Duration::from_secs(15))
            .build()
            .context("Failed to build reqwest client for proxy")?;
            
        Ok(client)
    }

    /// Build a host-pinned client for a specific proxy
    fn build_client_pinned(&self, proxy_str: &str, host: &str, ip: IpAddr, port: u16, user_agent: String) -> Result<Client> {
        let proxy = Proxy::all(proxy_str).context("Invalid proxy URL")?;
        
        let client = reqwest::Client::builder()
            .proxy(proxy)
            .user_agent(user_agent)
            .default_headers({
                let mut h = reqwest::header::HeaderMap::new();
                h.insert("Accept", HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"));
                h.insert("Accept-Language", HeaderValue::from_static("en-US,en;q=0.9"));
                h.insert("Sec-Ch-Ua", HeaderValue::from_static("\"Not A(Brand\";v=\"99\", \"Google Chrome\";v=\"122\", \"Chromium\";v=\"122\""));
                h.insert("Sec-Ch-Ua-Mobile", HeaderValue::from_static("?0"));
                h.insert("Sec-Ch-Ua-Platform", HeaderValue::from_static("\"Windows\""));
                h.insert("Sec-Fetch-Dest", HeaderValue::from_static("document"));
                h.insert("Sec-Fetch-Mode", HeaderValue::from_static("navigate"));
                h.insert("Sec-Fetch-Site", HeaderValue::from_static("none"));
                h.insert("Sec-Fetch-User", HeaderValue::from_static("?1"));
                h.insert("Upgrade-Insecure-Requests", HeaderValue::from_static("1"));
                h
            })
            .resolve(host, SocketAddr::new(ip, port))
            .danger_accept_invalid_certs(self.insecure)
            .timeout(Duration::from_secs(15))
            .build()
            .context("Failed to build host-pinned reqwest client for proxy")?;
            
        Ok(client)
    }

    fn pick_user_agent(&self) -> String {
        let mut rng = rand::thread_rng();
        self.user_agents.choose(&mut rng).cloned().unwrap_or_else(|| "Mozilla/5.0".to_string())
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
        
        let proxies_lock = self.lock_proxies();
        let available_proxies: Vec<String> = proxies_lock.iter()
            .filter(|p| {
                if let Some(entry) = self.blacklist.get(*p) {
                    if now < *entry.value() {
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

    /// V13: Get a random available managed exit node formatted as a SOCKS5/4 URL.
    pub fn get_best_socks_url(&self) -> Option<String> {
        let managed: Vec<String> = self.managed_exits.iter()
            .map(|e| e.key().clone())
            .collect();
            
        if !managed.is_empty() {
             let mut rng = rand::thread_rng();
             use rand::seq::SliceRandom;
             let ip = managed.choose(&mut rng)?;
             // DigitalOcean managed nodes run danted on 1080
             return Some(format!("socks5h://{}:1080", ip));
        }
        
        // Fallback to static proxies if they are SOCKS
        let best = self.pick_best_proxy()?;
        if best.starts_with("socks") {
            Some(best)
        } else {
            None
        }
    }

    /// V13: Wraps a std::process::Command with tool-specific proxy flags.
    pub fn wrap_command(&self, tool: &str, args: &mut Vec<String>) {
        if let Some(proxy_url) = self.get_best_socks_url() {
            match tool.to_lowercase().as_str() {
                "curl" => {
                    args.insert(0, "-x".to_string());
                    args.insert(1, proxy_url);
                }
                "nmap" => {
                    let nmap_proxy = proxy_url.replace("socks5h://", "socks4://");
                    args.push("--proxies".to_string());
                    args.push(nmap_proxy);
                }
                _ => {
                    warn!("ProxyManager: No native wrapping for tool '{}'. Traffic may leak!", tool);
                }
            }
        }
    }

    pub fn add_managed_exit(&self, ip: String) {
        self.managed_exits.insert(ip.clone(), std::time::SystemTime::now());
        info!("🚀 ProxyManager: Active DO Managed Exit added: {}", ip);
    }

    pub fn get_client(&self, host: &str) -> Option<(String, Client)> {
        if self.lock_proxies().is_empty() { return None; }

        let p_url = self.pick_best_proxy()?;
        
        // RT-Identity: Ensure same User-Agent for this host
        let ua = self.identity_cache.entry(host.to_string())
            .or_insert_with(|| self.pick_user_agent())
            .clone();

        use dashmap::mapref::entry::Entry;
        // Cache key includes User-Agent to ensure we don't reuse a client with a different UA if the cache is somehow cleared
        let cache_key = format!("{}:{}", p_url, ua);
        
        match self.clients.entry(cache_key) {
            Entry::Occupied(oe) => {
                Some((p_url, oe.get().clone()))
            }
            Entry::Vacant(ve) => {
                match self.build_client(&p_url, ua) {
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
        if self.lock_proxies().is_empty() { return None; }

        let p_url = self.pick_best_proxy()?;
        
        // RT-Identity: Ensure same User-Agent for this host
        let ua = self.identity_cache.entry(host.to_string())
            .or_insert_with(|| self.pick_user_agent())
            .clone();

        let cache_key = format!("{}:{}:{}:{}:{}", p_url, host, ip, port, ua);
        
        use dashmap::mapref::entry::Entry;
        match self.clients.entry(cache_key) {
            Entry::Occupied(oe) => {
                Some((p_url, oe.get().clone()))
            }
            Entry::Vacant(ve) => {
                match self.build_client_pinned(&p_url, host, ip, port, ua) {
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
        // Fixed jitter for blacklist: base 300s + rand 0..300
        let mut rng = rand::thread_rng();
        let jitter_max = if self.blacklist_duration_sec < 10 { 1 } else { 300 };
        let duration = self.blacklist_duration_sec + rand::Rng::gen_range(&mut rng, 0..jitter_max);

        // Insert the UNTIL timestamp
        self.blacklist.insert(proxy.to_string(), now + duration);
        warn!("Proxy temporarily blacklisted (jittered: {}s): {}", duration, proxy);
        
        // Penalize latency stats on blacklist
        let mut stats = self.latency_stats.entry(proxy.to_string()).or_insert_with(VecDeque::new);
        stats.push_back(10000); // Massive penalty (10s)
        if stats.len() > MAX_LATENCY_SAMPLES {
            stats.pop_front();
        }
    }

    /// STEALTH-001: Generates a "Human-like" delay using a Log-Normal distribution.
    /// This emulates the natural variation in human browsing/interaction speed.
    pub fn get_human_delay(&self) -> Duration {
        use rand_distr::{Distribution, LogNormal};
        let mut rng = rand::thread_rng();
        
        // LogNormal(μ, σ)
        // μ = 1.0, σ = 0.5 leads to values mostly between 1s and 5s with a long tail
        let normal = LogNormal::new(1.0, 0.5).unwrap();
        let sample = normal.sample(&mut rng);
        
        Duration::from_millis((sample * 1000.0) as u64)
    }

    /// STEALTH-002: Adaptive Jitter based on proxy reputation and target proximity.
    /// If a proxy is frequently blacklisted, it increases the delay to cool down.
    pub fn get_adaptive_delay(&self, proxy: &str) -> Duration {
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
            // Since we use &self, start_health_checker might need to be called differently if pm is already constructed.
            // But usually health checker is already running if there were proxies, or it will start on next call if we adapt it.
        }
    }

    pub fn is_empty(&self) -> bool {
        self.lock_proxies().is_empty()
    }
}

// QA-007 FIX: Abort the background health checker task when ProxyManager is dropped
impl Drop for ProxyManager {
    fn drop(&mut self) {
        if let Some(handle) = self._health_checker_handle.take() {
            handle.abort();
        }
    }
}

// Tests
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_proxy_manager_identity_bonding() {
        let p1 = "http://127.0.0.1:8080".to_string();
        let pm = ProxyManager::new(vec![p1.clone()], true);
        
        let host = "example.com";
        
        // First call should set the identity
        let (_, client1) = pm.get_client(host).unwrap();
        
        // Second call to same host should have same identity (User-Agent)
        // Note: reqwest Client doesn't easily expose UA, but we can verify it doesn't crash 
        // and we can trust the cache logic. For a real test we'd need a mock server.
        let (_, client2) = pm.get_client(host).unwrap();
        
        // We can check if the identity_cache has the entry
        assert!(pm.identity_cache.contains_key(host));
        let ua1 = pm.identity_cache.get(host).unwrap().clone();
        
        let (_, _client3) = pm.get_client(host).unwrap();
        let ua2 = pm.identity_cache.get(host).unwrap().clone();
        
        assert_eq!(ua1, ua2, "User-Agent changed for the same host!");
        
        // Different host should (statistically) get a different UA, or at least a new entry
        let host2 = "other.com";
        let (_, _) = pm.get_client(host2).unwrap();
        assert!(pm.identity_cache.contains_key(host2));
    }

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
            if let Some((url, _)) = pm.get_client("test.com") {
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
        assert!(pm.get_client("test.com").is_none());
        
        tokio::time::sleep(Duration::from_secs(2)).await;
        
        // Should recover
        assert!(pm.get_client("test.com").is_some());
    }

    #[tokio::test]
    async fn test_proxy_manager_concurrency() {
        let proxies = vec!["http://127.0.0.1:8080".to_string(), "http://127.0.0.1:8081".to_string()];
        let pm = Arc::new(ProxyManager::new(proxies, true));
        
        let mut handles = vec![];
        for i in 0..20 {
            let pm_clone = pm.clone();
            handles.push(tokio::spawn(async move {
                let host = format!("host{}.com", i % 3);
                let _ = pm_clone.get_client(&host);
            }));
        }
        
        for h in handles {
            let _ = h.await;
        }
    }
}
