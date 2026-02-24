use reqwest::{Client, Proxy};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use dashmap::DashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{warn, error};
use anyhow::{Result, Context};

pub struct ProxyManager {
    proxies: Vec<String>,
    clients: Arc<DashMap<String, Client>>,
    blacklist: Arc<DashMap<String, u64>>,
    current_index: Arc<AtomicUsize>,
    blacklist_duration_sec: u64,
    insecure: bool,
}

impl ProxyManager {
    pub fn new(proxies: Vec<String>, insecure: bool) -> Self {
        Self {
            proxies,
            clients: Arc::new(DashMap::new()),
            blacklist: Arc::new(DashMap::new()),
            current_index: Arc::new(AtomicUsize::new(0)),
            blacklist_duration_sec: 300,
            insecure,
        }
    }

    /// Internal method to lazily build a reqwest::Client for a specific proxy
    fn build_client(&self, proxy_str: &str) -> Result<Client> {
        let proxy = Proxy::all(proxy_str).context("Invalid proxy URL")?;
        
        let client = reqwest::Client::builder()
            .proxy(proxy)
            .danger_accept_invalid_certs(self.insecure)
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .context("Failed to build reqwest client for proxy")?;
            
        Ok(client)
    }

    /// Gets heavily reused pre-built reqwest::Client instances in a round-robin fashion,
    /// skipping blacklisted proxies.
    pub fn get_client(&self) -> Option<(String, Client)> {
        if self.proxies.is_empty() {
            return None;
        }

        let idx = self.current_index.fetch_add(1, Ordering::Relaxed) % self.proxies.len();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();

        for i in 0..self.proxies.len() {
            let p_idx = (idx + i) % self.proxies.len();
            let p_url = &self.proxies[p_idx];

            if let Some(timestamp) = self.blacklist.get(p_url) {
                if now - *timestamp < self.blacklist_duration_sec {
                    continue; // Still blacklisted
                } else {
                    drop(timestamp); // Free the reference before mutating the map
                    self.blacklist.remove(p_url); // Expired, give it a second chance
                }
            }

            // Fetch or build client lazily using Entry API for thread-safe initialization
            use dashmap::mapref::entry::Entry;
            match self.clients.entry(p_url.clone()) {
                Entry::Occupied(oe) => {
                    return Some((p_url.clone(), oe.get().clone()));
                }
                Entry::Vacant(ve) => {
                    match self.build_client(p_url) {
                        Ok(client) => {
                            ve.insert(client.clone());
                            return Some((p_url.clone(), client));
                        }
                        Err(e) => {
                            error!("Failed to initialize proxy {}: {}", p_url, e);
                            // Blacklist it immediately
                            self.blacklist_internal(p_url, now);
                        }
                    }
                }
            }
        }
        None // All proxies blacklisted or invalid
    }

    pub fn blacklist_proxy(&self, proxy: &str) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        self.blacklist_internal(proxy, now);
        warn!("Proxy temporarily blacklisted (timeout, 429, or 503): {}", proxy);
    }
    
    fn blacklist_internal(&self, proxy: &str, now: u64) {
        self.blacklist.insert(proxy.to_string(), now);
    }

    pub fn is_empty(&self) -> bool {
        self.proxies.is_empty()
    }
}

// Tests
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_manager_round_robin() {
        let proxies = vec!["http://127.0.0.1:8080".to_string(), "http://127.0.0.1:8081".to_string()];
        let pm = ProxyManager::new(proxies, true);

        let (url1, _) = pm.get_client().unwrap();
        let (url2, _) = pm.get_client().unwrap();
        let (url3, _) = pm.get_client().unwrap();
        
        assert_eq!(url1, "http://127.0.0.1:8080");
        assert_eq!(url2, "http://127.0.0.1:8081");
        assert_eq!(url3, "http://127.0.0.1:8080");
    }

    #[test]
    fn test_proxy_blacklist() {
        let proxies = vec!["http://127.0.0.1:8080".to_string()];
        let pm = ProxyManager::new(proxies, false);
        
        pm.blacklist_proxy("http://127.0.0.1:8080");
        
        // Should return None as the only proxy is blacklisted
        assert!(pm.get_client().is_none());
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
        
        // Ensure only 2 clients were initialized (one per proxy)
        assert!(pm.clients.len() <= 2);
    }
}
