use crate::plugins::ScannerPlugin;
use crate::models::{TargetHost, Finding, Severity, Category};
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::{info, warn};
use reqwest::Client;
use serde::Deserialize;
use std::sync::Arc;
use std::net::{IpAddr, SocketAddr};
use crate::utils::common::{HumanJitter, get_random_user_agent};
use crate::utils::proxy::ProxyManager;
use rand::seq::SliceRandom; 
use futures::StreamExt;

#[derive(Debug, Clone, Deserialize)]
struct WebSignature {
    title: String,
    severity: Severity,
    path: String,
    keyword: String,
}

impl WebSignature {
    fn load_default() -> Vec<Self> {
        vec![
            Self { 
                title: "Git Repository Exposed".into(), 
                severity: Severity::High, 
                path: "/.git/HEAD".into(), 
                keyword: "refs/heads".into() 
            },
            Self { 
                title: "Environment File Exposed".into(), 
                severity: Severity::Critical, 
                path: "/.env".into(), 
                keyword: "DB_PASSWORD".into() 
            },
            Self { 
                title: "DS_Store File Exposed".into(), 
                severity: Severity::Low, 
                path: "/.DS_Store".into(), 
                keyword: "Bud1".into() 
            },
            Self { 
                title: "PHP Info Page".into(), 
                severity: Severity::Medium, 
                path: "/phpinfo.php".into(), 
                keyword: "PHP Version".into() 
            },
        ]
    }
}

pub struct WebFuzzer {
    insecure: bool,
    signatures: Vec<WebSignature>,
    jitter: Arc<HumanJitter>,
    proxy_manager: Option<Arc<ProxyManager>>,
}

impl WebFuzzer {
    pub fn new(
        insecure: bool, 
        jitter: Arc<HumanJitter>,
        proxy_manager: Option<Arc<ProxyManager>>
    ) -> Self {
        Self {
            insecure,
            signatures: WebSignature::load_default(),
            jitter,
            proxy_manager,
        }
    }
    
    async fn get_target_client(&self, _target_host: &str, _target_ip: &str, is_https: bool, http_pinned: &Client, https_pinned: &Client) -> (Option<String>, Client) {
        if let Some(ref pm) = self.proxy_manager {
            if let Some((url, client)) = pm.get_client() {
                return (Some(url), client);
            }
        }
        if is_https {
            (None, https_pinned.clone())
        } else {
            (None, http_pinned.clone())
        }
    }

    async fn check_signature(&self, target_host: &str, target_ip: &str, sig: &WebSignature, http_pinned: &Client, https_pinned: &Client) -> Option<Finding> {
        let protocols = ["https", "http"];
        let max_retries = 3;
        
        for proto in protocols {
            let url = format!("{}://{}{}", proto, target_host, sig.path);
            let mut backoff_ms = 1000;
            
            for attempt in 0..max_retries {
                let is_https = proto == "https";
                let (proxy_url, client) = self.get_target_client(target_host, target_ip, is_https, http_pinned, https_pinned).await;
                
                // HIGH-002: Dynamic User-Agent rotation per request
                let res = client.get(&url)
                    .header("User-Agent", get_random_user_agent())
                    .header("X-Forwarded-For", "127.0.0.1") 
                    .send().await;
                
                match res {
                    Ok(resp) => {
                        let status = resp.status();
                        
                        if status.is_success() {
                            let text = resp.text().await.unwrap_or_default();
                            
                            if text.len() < 500 && (text.contains("not found") || text.to_lowercase().contains("error")) {
                                break; 
                            }
        
                            if text.contains(&sig.keyword) {
                                return Some(Finding::new(
                                    crate::models::FINDING_WEB_SIG_MATCH,
                                    Category::Vulnerability,
                                    sig.severity.clone(),
                                    &format!("Signature match: {}", sig.title),
                                    serde_json::json!({
                                        "url": url,
                                        "keyword": sig.keyword,
                                        "proxy_used": proxy_url
                                    })
                                ));
                            }
                            break; 
                        } else if status == 429 || status == 503 {
                            warn!("WebFuzzer: 429/503 detected on {}. Backing off...", target_host);
                            if let (Some(ref pm), Some(ref p_url)) = (&self.proxy_manager, &proxy_url) {
                                pm.blacklist_proxy(p_url);
                            }
                            
                            if attempt < max_retries - 1 {
                                tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
                                self.jitter.sleep().await;
                                backoff_ms *= 2;
                                continue;
                            }
                            break;
                        } else {
                            break; 
                        }
                    },
                    Err(e) => {
                        if e.is_connect() || e.is_timeout() {
                            if let (Some(ref pm), Some(ref p_url)) = (&self.proxy_manager, &proxy_url) {
                                pm.blacklist_proxy(p_url); 
                            }
                        }
                        
                        if attempt < max_retries - 1 {
                            self.jitter.sleep().await;
                            continue;
                        }
                        break;
                    }
                }
            }
        }
        None
    }
}

#[async_trait]
impl ScannerPlugin for WebFuzzer {
    fn name(&self) -> &'static str {
        crate::models::PLUGIN_WEB
    }

    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        info!("WebFuzzer analysis started for {}", target.host);
        
        let ip_str = match &target.ip {
            Some(i) => i.clone(),
            None => {
                warn!("WebFuzzer: No IP for {}, skipping.", target.host);
                return Ok(Vec::new());
            }
        };

        let ip: IpAddr = ip_str.parse().context("Failed to parse target IP")?;

        // SSRF FIX: Build host-pinned clients to prevent DNS rebinding for both HTTP and HTTPS
        // reqwest's resolve() is port-specific, so we need two clients if we want to pin both.
        let pinned_http = Client::builder()
            .danger_accept_invalid_certs(self.insecure)
            .redirect(reqwest::redirect::Policy::limited(3))
            .timeout(std::time::Duration::from_secs(10))
            .user_agent(get_random_user_agent())
            .resolve(&target.host, SocketAddr::new(ip, 80))
            .build()
            .context("Failed to build pinned WebFuzzer client (HTTP)")?;

        let pinned_https = Client::builder()
            .danger_accept_invalid_certs(self.insecure)
            .redirect(reqwest::redirect::Policy::limited(3))
            .timeout(std::time::Duration::from_secs(10))
            .user_agent(get_random_user_agent())
            .resolve(&target.host, SocketAddr::new(ip, 443))
            .build()
            .context("Failed to build pinned WebFuzzer client (HTTPS)")?;

        // P0 FIX: Strict Randomize signature traversal order
        let mut shuffled_sigs = self.signatures.clone();
        shuffled_sigs.shuffle(&mut rand::thread_rng());

        // MED-002 FIX: Concurrent Signature Checking (Refactored to avoid Async Mutex)
        let jitter = self.jitter.clone();
        let target_host = target.host.clone();
        let target_ip_str = ip_str.clone();
        
        let http_client = pinned_http.clone();
        let https_client = pinned_https.clone();

        let findings_stream = futures::stream::iter(shuffled_sigs)
            .map(|sig| {
                let jitter_clone = jitter.clone();
                let host = target_host.clone();
                let ip_clone = target_ip_str.clone();
                let client_http = http_client.clone();
                let client_https = https_client.clone();
                
                async move {
                    jitter_clone.sleep().await;
                    if let Some(finding) = self.check_signature(&host, &ip_clone, &sig, &client_http, &client_https).await {
                        info!("🚨 Vuln found on {}: {}", host, sig.title);
                        Some(finding)
                    } else {
                        None
                    }
                }
            })
            .buffer_unordered(10);
            
        let final_findings: Vec<Finding> = findings_stream
            .filter_map(|f| async move { f })
            .collect()
            .await;

        Ok(final_findings)
    }
}

// Tests
#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::common::HumanJitter;

    #[tokio::test]
    async fn test_web_fuzzer_instantiation() {
        let jitter = Arc::new(HumanJitter::new(1, 2));
        let fuzzer = WebFuzzer::new(true, jitter, None);
        assert_eq!(fuzzer.name(), crate::models::PLUGIN_WEB);
    }
}
