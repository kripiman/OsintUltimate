use rand_distr::{LogNormal, Distribution};
use tokio::time::{sleep, Duration};
use tracing::warn;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct HumanJitter {
    min_delay_ms: f64, // Changed to float for LogNormal calc
    max_delay_ms: f64,
    dist: LogNormal<f64>,
}

impl HumanJitter {
    pub fn new(min_delay_ms: u64, max_delay_ms: u64) -> Self {
        // LogNormal params: mean=0.5, std_dev=0.8 (simulating human reaction)
        let dist = LogNormal::new(0.5, 0.8).unwrap();
        Self {
            min_delay_ms: min_delay_ms as f64,
            max_delay_ms: max_delay_ms as f64,
            dist,
        }
    }

    pub async fn sleep(&self) {
        let base_delay = self.dist.sample(&mut rand::thread_rng()) * 1000.0; // Scale factor
        let delay = base_delay.clamp(self.min_delay_ms, self.max_delay_ms);
        sleep(Duration::from_millis(delay as u64)).await;
    }
}

pub struct ProxyManager {
    proxies: Vec<String>,
    blacklist: Arc<Mutex<HashMap<String, u64>>>, // Proxy -> Timestamp (when blocked)
    current_index: Arc<Mutex<usize>>,
    blacklist_duration_sec: u64,
}

impl ProxyManager {
    pub fn new(proxies: Vec<String>) -> Self {
        Self {
            proxies,
            blacklist: Arc::new(Mutex::new(HashMap::new())),
            current_index: Arc::new(Mutex::new(0)),
            blacklist_duration_sec: 300,
        }
    }

    pub fn get_next_proxy(&self) -> Option<String> {
        if self.proxies.is_empty() {
            return None;
        }

        let mut idx_guard = self.current_index.lock().unwrap();
        let mut bl_guard = self.blacklist.lock().unwrap();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        // Simple round-robin with blacklist check
        for _ in 0..self.proxies.len() {
            let p = &self.proxies[*idx_guard];
            *idx_guard = (*idx_guard + 1) % self.proxies.len();

            if let Some(timestamp) = bl_guard.get(p) {
                if now - timestamp < self.blacklist_duration_sec {
                    continue; // Still blacklisted
                } else {
                    bl_guard.remove(p); // Expired
                }
            }
            return Some(p.clone());
        }
        None // All blacklisted
    }

    pub fn blacklist_proxy(&self, proxy: &str) {
        let mut bl_guard = self.blacklist.lock().unwrap();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        bl_guard.insert(proxy.to_string(), now);
        warn!("Proxy blacklisted: {}", proxy);
    }

    pub fn get_all_proxies(&self) -> Vec<String> {
        self.proxies.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_manager_round_robin() {
        let proxies = vec!["http://p1".to_string(), "http://p2".to_string()];
        let pm = ProxyManager::new(proxies);

        assert_eq!(pm.get_next_proxy().unwrap(), "http://p1");
        assert_eq!(pm.get_next_proxy().unwrap(), "http://p2");
        assert_eq!(pm.get_next_proxy().unwrap(), "http://p1");
    }

    #[test]
    fn test_proxy_blacklist() {
        let proxies = vec!["http://p1".to_string()];
        let pm = ProxyManager::new(proxies);
        
        pm.blacklist_proxy("http://p1");
        
        // Should return None as p1 is blacklisted
        assert!(pm.get_next_proxy().is_none());
    }
    
    #[tokio::test]
    async fn test_jitter_range() {
        let jitter = HumanJitter::new(10, 20);
        // We can't easily test duration without mocking time or statistical analysis.
        // But we can ensure it doesn't panic.
        jitter.sleep().await;
        // Pass
    }
}
