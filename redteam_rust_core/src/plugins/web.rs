use crate::plugins::ScannerPlugin;
use crate::models::{TargetHost, Finding, Severity, Category};
use crate::utils::{HumanJitter, ProxyManager};
use async_trait::async_trait;
use anyhow::Result;
use tracing::{info, debug, warn};
use std::sync::Arc;
use reqwest::Client;
use dashmap::DashMap;

pub struct WebFuzzer {
    // Pool of clients for proxy support: ProxyURL -> Client
    client_pool: Arc<DashMap<String, Client>>,
    default_client: Client,
    jitter: HumanJitter,
    signatures: Vec<Signature>,
    user_agents: Vec<String>,
    proxy_manager: Option<Arc<ProxyManager>>,
    insecure: bool, // Added field
}

struct Signature {
    endpoint: String,
    keyword: String,
    title: String,
    severity: Severity,
}

impl WebFuzzer {
    pub fn new(insecure: bool) -> Self { // Updated signature
        let signatures = vec![
            Signature { endpoint: "/.env".into(), keyword: "APP_KEY=".into(), title: "Laravel .env Exposure".into(), severity: Severity::Critical },
            Signature { endpoint: "/.git/config".into(), keyword: "[core]".into(), title: "Git Config Exposure".into(), severity: Severity::High },
            Signature { endpoint: "/wp-config.php.bak".into(), keyword: "DB_PASSWORD".into(), title: "WP Backup Exposure".into(), severity: Severity::Critical },
            Signature { endpoint: "/.aws/credentials".into(), keyword: "[default]".into(), title: "AWS Credentials Exposure".into(), severity: Severity::Critical },
        ];

        let user_agents = vec![
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36".into()
        ];
        
        let default_client = Client::builder()
            .danger_accept_invalid_certs(insecure) // Use flag
            .redirect(reqwest::redirect::Policy::limited(3))
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("Failed to build default client");

        Self {
            client_pool: Arc::new(DashMap::new()),
            default_client,
            jitter: HumanJitter::new(300, 2000), 
            signatures,
            user_agents,
            proxy_manager: None,
            insecure,
        }
    }

    pub fn with_proxies(mut self, proxies: Vec<String>) -> Self {
        if !proxies.is_empty() {
            self.proxy_manager = Some(Arc::new(ProxyManager::new(proxies)));
            info!("WebFuzzer configured with proxies");
        }
        self
    }
    
    pub async fn validate_proxies(&self) {
        if let Some(pm) = &self.proxy_manager {
            info!("Validating proxies...");
            let proxies = pm.get_all_proxies();
            for proxy in proxies {
                let client = self.get_client(Some(&proxy));
                // Check against a reliable target (e.g., google.com or httpbin)
                // Using httpbin.org/ip is common but might be rate limited. 
                // Using a simple head request to google.
                if let Err(e) = client.head("http://www.google.com").send().await {
                    warn!("Proxy {} failed health check: {}", proxy, e);
                    pm.blacklist_proxy(&proxy).await;
                } else {
                    debug!("Proxy {} is healthy", proxy);
                }
            }
        }
    }
    
    fn get_ua(&self) -> &str {
        use rand::seq::SliceRandom;
        self.user_agents.choose(&mut rand::thread_rng()).unwrap()
    }

    fn get_client(&self, proxy: Option<&str>) -> Client {
        if let Some(p) = proxy {
            // Check pool
            if let Some(client) = self.client_pool.get(p) {
                return client.clone();
            }
            
            // Build new client
            let proxy_obj = match reqwest::Proxy::all(p) {
                Ok(proxy) => proxy,
                Err(e) => {
                    warn!("Invalid proxy URL '{}': {}", p, e);
                    return self.default_client.clone();
                }
            };

            let client = Client::builder()
                .proxy(proxy_obj)
                .danger_accept_invalid_certs(self.insecure) // Use flag
                .redirect(reqwest::redirect::Policy::limited(3))
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap_or_else(|_| self.default_client.clone()); // Fallback if proxy fails to init

            self.client_pool.insert(p.to_string(), client.clone());
            client
        } else {
            self.default_client.clone()
        }
    }

    async fn check_signature(&self, target_host: &str, sig: &Signature) -> Option<Finding> {
        // Try HTTPS first, then HTTP
        let protocols = ["https", "http"];
        
        for proto in protocols {
            let url = format!("{}://{}{}", proto, target_host, sig.endpoint);
        let ua = self.get_ua();
        
        self.jitter.sleep().await;

        let proxy = if let Some(pm) = &self.proxy_manager {
            pm.get_next_proxy().await
        } else {
            None
        };
        
        // Use client pool
        let client = self.get_client(proxy.as_deref());
        
        // Retry Loop (3 attempts)
        let mut attempts = 0;
        loop {
            attempts += 1;
            match client.get(&url).header("User-Agent", ua).send().await {
                Ok(resp) => {
                     if resp.status().is_success() {
                         let status = resp.status();
                         let text = resp.text().await.unwrap_or_default();
                         
                         if text.len() < 1200 && (text.contains("not found") || text.contains("error 404")) {
                             return None;
                         }
    
                         if text.contains(&sig.keyword) {
                             return Some(Finding::new(
                                 "WEB-SIG-MATCH",
                                 Category::Vulnerability,
                                 sig.severity.clone(),
                                 &format!("Signature match: {}", sig.title),
                                 serde_json::json!({
                                     "url": url,
                                     "status": status.as_u16(),
                                     "keyword": sig.keyword,
                                     "proxy_used": proxy
                                 })
                             ));
                         }
                     }
                     break; // Success or non-matching success, exit loop
                },
                Err(e) => {
                    if attempts >= 3 {
                        debug!("Request failed after 3 attempts: {}", e);
                        // If proxy failed, blacklist it
                        if let Some(p) = &proxy {
                            if let Some(pm) = &self.proxy_manager {
                                pm.blacklist_proxy(p).await;
                            }
                        }
                        break;
                    }
                    // Exponential backoff: 500ms, 1000ms...
                    let wait = 500 * (1 << (attempts - 1));
                    tokio::time::sleep(tokio::time::Duration::from_millis(wait)).await;
                }
            }
        } // End retry loop
        } // End protocols loop
        None
    }
}

#[async_trait]
impl ScannerPlugin for WebFuzzer {
    fn name(&self) -> &'static str {
        "WebFuzzer"
    }

    async fn scan(&self, target: &mut TargetHost) -> Result<()> {
        info!("WebFuzzer analysis started for {}", target.host);
        
        for sig in &self.signatures {
            if let Some(finding) = self.check_signature(&target.host, sig).await {
                info!("🚨 Vuln found on {}: {}", target.host, sig.title);
                target.findings.push(finding);
            }
        }
        
        Ok(())
    }
}
