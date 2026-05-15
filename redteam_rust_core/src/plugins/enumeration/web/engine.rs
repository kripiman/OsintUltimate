use crate::plugins::{ScannerPlugin, Capability};
use crate::models::{TargetHost, Finding, Severity, Category};
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::{info, warn};
use reqwest::Client;
use serde::Deserialize;
use std::sync::Arc;
use std::net::{IpAddr, SocketAddr};
use crate::utils::common::HumanJitter;
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
        vec![Self { 
                title: "Git Repository Exposed".into(), severity: Severity::High, path: "/.git/HEAD".into(), keyword: "refs/heads".into() 
            }, Self { 
                title: "Environment File Exposed".into(), severity: Severity::Critical, path: "/.env".into(), keyword: "DB_PASSWORD".into() 
            }, Self { 
                title: "DS_Store File Exposed".into(), severity: Severity::Low, path: "/.DS_Store".into(), keyword: "Bud1".into() 
            }, Self { 
                title: "PHP Info Page".into(), severity: Severity::Medium, path: "/phpinfo.php".into(), keyword: "PHP Version".into() 
            }, ]
    }
}

pub struct WebFuzzer {
    _insecure: bool,
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
            _insecure: insecure,
            signatures: WebSignature::load_default(),
            jitter,
            proxy_manager,
        }
    }
    
    async fn get_target_client(&self, target_host: &str, target_ip: &str, is_https: bool, http_pinned: &Client, https_pinned: &Client) -> (Option<String>, Client) {
        if let Some(ref pm) = self.proxy_manager {
            let port = if is_https { 443 } else { 80 };
            if let Ok(ip) = target_ip.parse::<IpAddr>() {
                if let Some((url, client)) = pm.get_stealth_client_pinned(target_host, ip, port) {
                    return (Some(url), client);
                }
            } else {
                warn!("WebFuzzer: Failed to parse target IP {} for pinning", target_ip);
                if let Some((url, client)) = pm.get_stealth_client(target_host) {
                    return (Some(url), client);
                }
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
                
                // RT-Identity: If proxy is used, we rely on the Client's internal bonded UA.
                // Otherwise, we can still use random UA for direct connections (or keep it consistent if preferred).
                let mut request = client.get(&url);
                let start_time = std::time::Instant::now();
                if proxy_url.is_none() {
                    request = request.header(reqwest::header::USER_AGENT, crate::utils::common::get_random_user_agent());
                }
                
                let res = request.send().await;
                
                let duration = start_time.elapsed().as_millis() as u64;

                if let (Some(ref pm), Some(ref p_url)) = (&self.proxy_manager, &proxy_url) {
                    pm.report_latency(p_url, duration);
                }
                
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
                            if let (Some(_pm), Some(_p_url)) = (&self.proxy_manager, &proxy_url) {
                                // Blacklist logic removed per Auditor request
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
                            if let (Some(_pm), Some(_p_url)) = (&self.proxy_manager, &proxy_url) {
                                // Blacklist logic removed per Auditor request
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

        fn metadata(&self) -> crate::plugins::PluginMetadata {
        crate::plugins::PluginMetadata {
            name: self.name().to_string(),
            description: "Fast web fuzzing for sensitive files (.env, .git, etc.) with jitter and proxy support.".to_string(),
            target_type: crate::plugins::TargetType::Web,
            risk_level: crate::plugins::RiskLevel::Medium,
            layer: crate::core::capability_layer::ScanLayer::Scanning, // ← NUEVO
            expected_duration: std::time::Duration::from_secs(300),
            capabilities: self.capabilities(),
            cost: 5,
            category: "Enumeration".to_string(),
            mitre_attacks: vec![],
            exploit_difficulty: crate::plugins::RiskLevel::Medium,
            blackarch_category: None,
            is_destructive: false,
            poc_mode: false, ..Default::default() }
    }
    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::VulnerabilityScanning]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability("web").await)
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

        let pm = self.proxy_manager.as_ref().context("V14.1 OPSEC Violation: WebFuzzer requires ProxyManager for tactical execution")?;

        // SSRF FIX: Build host-pinned clients to prevent DNS rebinding for both HTTP and HTTPS
        // Use StealthClientBuilder to apply tactical context (AI bypass suggestions)
        let pinned_http = crate::utils::stealth_http::StealthClientBuilder::build_pinned(
            target, 
            pm,
            &target.host, 
            SocketAddr::new(ip, 80)
        ).context("Failed to build tactical pinned client (HTTP)")?;

        let pinned_https = crate::utils::stealth_http::StealthClientBuilder::build_pinned(
            target, 
            pm,
            &target.host, 
            SocketAddr::new(ip, 443)
        ).context("Failed to build tactical pinned client (HTTPS)")?;

        // P0 FIX: Strict Randomize signature traversal order
        let mut indices: Vec<usize> = (0..self.signatures.len()).collect();
        indices.shuffle(&mut rand::thread_rng());

        // MED-002 FIX: Concurrent Signature Checking (Refactored to avoid Async Mutex)
        let jitter = self.jitter.clone();
        let target_host = target.host.clone();
        let target_ip_str = ip_str.clone();
        
        let http_client = pinned_http.clone();
        let https_client = pinned_https.clone();

        let findings_stream = futures::stream::iter(indices)
            .map(|idx| {
                let sig = &self.signatures[idx];
                let j = jitter.clone();
                let host = target_host.clone();
                let ip_clone = target_ip_str.clone();
                let client_http = http_client.clone();
                let client_https = https_client.clone();
                
                async move {
                    j.sleep().await; // Sleep sequentially before resolving futures upstream
                    if let Some(finding) = self.check_signature(&host, &ip_clone, sig, &client_http, &client_https).await {
                        info!("🚨 Vuln found on {}: {}", host, sig.title);
                        Some(finding)
                    } else {
                        None
                    }
                }
            })
            .buffer_unordered(self.signatures.len().min(10)); // QA-009: Derive from signature count
            
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
