use crate::plugins::{Capability, DiscoveryPlugin, DiscoveryResult, PluginMetadata, RiskLevel, TargetType};
use crate::models::{TargetHost, PLUGIN_FAVICON_HASH};
use crate::utils::api_budget::ApiBudgetRegistry;
use crate::utils::config::Config;
use crate::utils::shodan_keyring::ShodanKeyring;
use async_trait::async_trait;
use anyhow::Result;
use tracing::{info, warn, debug};
use std::io::Cursor;
use std::time::Duration;
use base64::{engine::general_purpose::URL_SAFE, Engine as _};

const FAVICON_TIMEOUT_SECS: u64 = 10;
const API_TIMEOUT_SECS: u64 = 15;

pub struct FaviconHashScanner {
    client: reqwest::Client,
    shodan_max_hosts: usize,
    fofa_max_hosts: usize,
    fofa_email: Option<String>,
    fofa_key: Option<String>,
    /// Base URL for Shodan API (injected for testing).
    shodan_base_url: String,
    /// Base URL for FOFA API (injected for testing).
    fofa_base_url: String,
}

impl Default for FaviconHashScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl FaviconHashScanner {
    pub fn new() -> Self {
        let config = Config::from_env();
        Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(FAVICON_TIMEOUT_SECS))
                .build()
                .expect("reqwest::Client builder must not fail"),
            shodan_max_hosts: config.shodan_paid_max_hosts_per_scan,
            fofa_max_hosts: config.fofa_max_hosts_per_scan,
            fofa_email: config.fofa_email,
            fofa_key: config.fofa_api_key,
            shodan_base_url: "https://api.shodan.io".to_string(),
            fofa_base_url: "https://fofa.info".to_string(),
        }
    }

    #[cfg(test)]
    pub fn with_params(
        client: reqwest::Client,
        shodan_max_hosts: usize,
        fofa_max_hosts: usize,
        fofa_email: Option<String>,
        fofa_key: Option<String>,
    ) -> Self {
        Self {
            client,
            shodan_max_hosts,
            fofa_max_hosts,
            fofa_email,
            fofa_key,
            shodan_base_url: "https://api.shodan.io".to_string(),
            fofa_base_url: "https://fofa.info".to_string(),
        }
    }

    #[cfg(test)]
    pub fn with_base_urls(
        mut self,
        shodan_base_url: String,
        fofa_base_url: String,
    ) -> Self {
        self.shodan_base_url = shodan_base_url;
        self.fofa_base_url = fofa_base_url;
        self
    }

    /// Compute the Shodan-compatible favicon hash (MMH3 signed 32-bit).
    ///
    /// Shodan does NOT hash raw bytes. It hashes the base64-encoded content
    /// with LF newlines every 76 characters plus a trailing LF (RFC 2045
    /// style, matching Python `base64.encodebytes`).
    fn compute_hash(bytes: &[u8]) -> i32 {
        let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
        let mut with_newlines = String::with_capacity(encoded.len() + encoded.len() / 76 + 1);
        for chunk in encoded.as_bytes().chunks(76) {
            with_newlines.push_str(std::str::from_utf8(chunk).unwrap_or(""));
            with_newlines.push('\n');
        }
        let mut cursor = Cursor::new(with_newlines);
        let hash_u32 = murmur3::murmur3_32(&mut cursor, 0).unwrap_or(0);
        hash_u32 as i32
    }

    async fn fetch_favicon(&self, host: &str) -> Option<Vec<u8>> {
        for scheme in ["https", "http"] {
            let url = format!("{}://{}/favicon.ico", scheme, host);
            debug!("FaviconHashScanner: fetching {}", url);
            match self.client.get(&url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    match resp.bytes().await {
                        Ok(bytes) if !bytes.is_empty() => return Some(bytes.to_vec()),
                        _ => continue,
                    }
                }
                Ok(resp) => {
                    debug!("FaviconHashScanner: {} returned HTTP {}", url, resp.status());
                    continue;
                }
                Err(e) => {
                    debug!("FaviconHashScanner: fetch error for {}: {}", url, e);
                    continue;
                }
            }
        }
        None
    }

    async fn pivot_shodan(&self, hash: i32) -> Vec<DiscoveryResult> {
        if self.shodan_max_hosts == 0 {
            return Vec::new();
        }
        let key = match ShodanKeyring::get().get_key_for_search() {
            Some(k) => k,
            _ => {
                debug!("FaviconHashScanner: no Shodan search key available");
                return Vec::new();
            }
        };
        if !ApiBudgetRegistry::get().can_spend("shodan_paid", 1).await {
            return Vec::new();
        }

        let query = format!("http.favicon.hash:{}", hash);
        let url = format!("{}/shodan/host/search", self.shodan_base_url.trim_end_matches('/'));

        let mut discovered = Vec::new();
        if let Ok(resp) = self.client
            .get(&url)
            .timeout(Duration::from_secs(API_TIMEOUT_SECS))
            .query(&[("key", key), ("query", &query), ("minify", "true")])
            .send()
            .await
        {
            #[derive(serde::Deserialize)]
            struct ShodanMatch {
                ip_str: Option<String>,
                hostnames: Option<Vec<String>>,
            }
            #[derive(serde::Deserialize)]
            struct ShodanSearchResp {
                matches: Option<Vec<ShodanMatch>>,
            }
            if let Ok(data) = resp.json::<ShodanSearchResp>().await {
                if let Some(matches) = data.matches {
                    for m in matches {
                        if let Some(ip) = m.ip_str {
                            discovered.push(DiscoveryResult {
                                host: ip.clone(),
                                metadata: serde_json::json!({
                                    "asset_type": "related_asset",
                                    "source": "shodan",
                                    "pivot": "http.favicon.hash",
                                    "favicon_hash": hash,
                                    "hostnames": m.hostnames.unwrap_or_default(),
                                }),
                            });
                        }
                        if discovered.len() >= self.shodan_max_hosts {
                            break;
                        }
                    }
                }
            }
        }
        discovered
    }

    async fn pivot_fofa(&self, hash: i32) -> Vec<DiscoveryResult> {
        if self.fofa_max_hosts == 0 {
            return Vec::new();
        }
        let (email, key) = match (&self.fofa_email, &self.fofa_key) {
            (Some(e), Some(k)) if !e.is_empty() && !k.is_empty() => (e, k),
            _ => return Vec::new(),
        };
        if !ApiBudgetRegistry::get().can_spend("fofa", 1).await {
            return Vec::new();
        }

        let query = format!("icon_hash=\"{}\"", hash);
        let qbase64 = URL_SAFE.encode(&query);
        let url = format!("{}/api/v1/search/all", self.fofa_base_url.trim_end_matches('/'));
        let size = self.fofa_max_hosts.min(1000).to_string();

        let mut discovered = Vec::new();
        if let Ok(resp) = self.client
            .get(&url)
            .timeout(Duration::from_secs(API_TIMEOUT_SECS))
            .query(&[
                ("email", email.as_str()),
                ("key", key.as_str()),
                ("qbase64", qbase64.as_str()),
                ("fields", "host,ip"),
                ("size", &size),
                ("page", "1"),
            ])
            .send()
            .await
        {
            if resp.status().is_success() {
                #[derive(serde::Deserialize)]
                struct FofaResp {
                    results: Option<Vec<Vec<String>>>,
                }
                if let Ok(data) = resp.json::<FofaResp>().await {
                    if let Some(results) = data.results {
                        for row in results {
                            // FOFA fields=host,ip => row[0]=host, row[1]=ip
                            let host = row.get(0).cloned().unwrap_or_default();
                            let ip = row.get(1).cloned().unwrap_or_default();
                            let clean_host = host
                                .replace("http://", "")
                                .replace("https://", "");
                            if !clean_host.is_empty() {
                                discovered.push(DiscoveryResult {
                                    host: clean_host,
                                    metadata: serde_json::json!({
                                        "asset_type": "related_asset",
                                        "source": "fofa",
                                        "pivot": "icon_hash",
                                        "favicon_hash": hash,
                                        "ip": ip,
                                    }),
                                });
                            }
                            if discovered.len() >= self.fofa_max_hosts {
                                break;
                            }
                        }
                    }
                }
            } else {
                warn!("FaviconHashScanner: FOFA API returned HTTP {}", resp.status());
            }
        }
        discovered
    }
}

#[async_trait]
impl DiscoveryPlugin for FaviconHashScanner {
    fn name(&self) -> &'static str {
        PLUGIN_FAVICON_HASH
    }

    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: self.name().to_string(),
            description: "Favicon hash asset discovery: computes MMH3 hash of /favicon.ico and pivots via Shodan (http.favicon.hash) and FOFA (icon_hash) to discover related assets.".to_string(),
            target_type: TargetType::Web,
            risk_level: RiskLevel::Safe,
            layer: crate::core::capability_layer::ScanLayer::Passive,
            expected_duration: Duration::from_secs(30),
            capabilities: self.capabilities(),
            cost: 2,
            category: "Reconnaissance".to_string(),
            mitre_attacks: vec!["T1590".to_string()],
            exploit_difficulty: RiskLevel::Safe,
            blackarch_category: Some("recon".to_string()),
            is_destructive: false,
            poc_mode: false, // Discovery plugin has no PoC concept
            ..Default::default()
        }
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::FaviconAssetDiscovery]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        // Dependency check: at least one pivot source must be configured.
        let has_shodan = ShodanKeyring::get().get_key_for_search().is_some();
        let has_fofa = self.fofa_email.is_some()
            && self.fofa_key.is_some()
            && self.fofa_max_hosts > 0;
        Ok(has_shodan || has_fofa)
    }

    async fn discover(&self, target: &TargetHost) -> Result<Vec<DiscoveryResult>> {
        info!("FaviconHashScanner: discovering related assets for {}", target.host);

        let favicon_bytes = match self.fetch_favicon(&target.host).await {
            Some(b) => b,
            None => {
                debug!("FaviconHashScanner: no favicon found for {}", target.host);
                return Ok(Vec::new());
            }
        };

        let hash = Self::compute_hash(&favicon_bytes);
        debug!("FaviconHashScanner: hash for {} = {}", target.host, hash);

        let mut results = Vec::new();
        results.extend(self.pivot_shodan(hash).await);
        results.extend(self.pivot_fofa(hash).await);

        info!(
            "FaviconHashScanner: discovered {} related assets for {} via hash {}",
            results.len(),
            target.host,
            hash
        );
        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{MockServer, Mock, ResponseTemplate};
    use wiremock::matchers::{method, path, query_param};

    #[test]
    fn test_compute_hash_known_value() {
        // Shodan hashes base64-encoded data with RFC 2045 newlines, not raw bytes.
        // Values verified against Python mmh3 + base64.encodebytes().
        let hash = FaviconHashScanner::compute_hash(b"");
        assert_eq!(hash, 0); // base64.encodebytes(b"") == b"\n" => mmh3 = 0

        let hash = FaviconHashScanner::compute_hash(b"hello");
        assert_eq!(hash, 1155597304);
    }

    #[test]
    fn test_compute_hash_signed_conversion() {
        // Verify signed i32 output matches Python mmh3 signed output.
        let hash = FaviconHashScanner::compute_hash(&[0xff, 0xff, 0xff, 0xff]);
        assert_eq!(hash, 147229587);
    }

    #[tokio::test]
    async fn test_fetch_favicon_success() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/favicon.ico"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"fake-icon-data"))
            .mount(&server)
            .await;

        let scanner = FaviconHashScanner::with_params(
            reqwest::Client::new(),
            0,
            0,
            None,
            None,
        );
        let uri = server.uri();
        let host = uri.trim_start_matches("http://");
        let result = scanner.fetch_favicon(host).await;
        assert!(result.is_some());
        assert_eq!(result.unwrap(), b"fake-icon-data");
    }

    #[tokio::test]
    async fn test_fetch_favicon_404() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/favicon.ico"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let scanner = FaviconHashScanner::with_params(
            reqwest::Client::new(),
            0,
            0,
            None,
            None,
        );
        let uri = server.uri();
        let host = uri.trim_start_matches("http://");
        let result = scanner.fetch_favicon(host).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_pivot_shodan_respects_max_hosts() {
        let scanner = FaviconHashScanner::with_params(
            reqwest::Client::new(),
            0, // max_hosts = 0 disables Shodan
            0,
            None,
            None,
        );
        let results = scanner.pivot_shodan(12345).await;
        assert!(results.is_empty(), "Shodan pivot should be disabled when max_hosts=0");
    }

    #[tokio::test]
    async fn test_pivot_shodan_success() {
        // Initialize global registries required by pivot_shodan.
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| {
            let mut config = Config::from_env();
            config.shodan_api_key = Some("dummy_shodan_key".to_string());
            ShodanKeyring::init(&config);
            ApiBudgetRegistry::init(&config, None);
        });

        let server = MockServer::start().await;
        let hash = 12345i32;
        let query = format!("http.favicon.hash:{}", hash);

        Mock::given(method("GET"))
            .and(path("/shodan/host/search"))
            .and(query_param("query", &query))
            .and(query_param("key", "dummy_shodan_key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "matches": [
                    {"ip_str": "1.2.3.4", "hostnames": ["a.example.com"]},
                    {"ip_str": "5.6.7.8", "hostnames": null}
                ]
            })))
            .mount(&server)
            .await;

        let scanner = FaviconHashScanner::with_params(
            reqwest::Client::new(),
            5,
            0,
            None,
            None,
        ).with_base_urls(
            server.uri(), // shodan base url
            "https://fofa.info".to_string(),
        );
        let results = scanner.pivot_shodan(hash).await;
        assert_eq!(results.len(), 2, "Shodan pivot should return 2 matches");
        assert_eq!(results[0].host, "1.2.3.4");
        assert_eq!(results[0].metadata["source"], "shodan");
        assert_eq!(results[0].metadata["favicon_hash"], 12345);
        assert_eq!(
            results[0].metadata["hostnames"],
            serde_json::json!(["a.example.com"])
        );
        assert_eq!(results[1].host, "5.6.7.8");
    }

    #[tokio::test]
    async fn test_pivot_fofa_respects_max_hosts() {
        let scanner = FaviconHashScanner::with_params(
            reqwest::Client::new(),
            0,
            0, // max_hosts = 0 disables FOFA
            Some("test@example.com".to_string()),
            Some("secret".to_string()),
        );
        let results = scanner.pivot_fofa(12345).await;
        assert!(results.is_empty(), "FOFA pivot should be disabled when max_hosts=0");
    }

    #[tokio::test]
    async fn test_pivot_fofa_missing_creds() {
        let scanner = FaviconHashScanner::with_params(
            reqwest::Client::new(),
            0,
            10,
            None,
            None,
        );
        let results = scanner.pivot_fofa(12345).await;
        assert!(results.is_empty(), "FOFA pivot should return empty when creds missing");
    }

    #[tokio::test]
    async fn test_pivot_fofa_success() {
        // Initialize global budget registry required by pivot_fofa.
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| {
            let config = Config::from_env();
            ApiBudgetRegistry::init(&config, None);
        });

        let server = MockServer::start().await;
        let hash = 54321i32;
        let query = format!("icon_hash=\"{}\"", hash);
        let qbase64 = URL_SAFE.encode(&query);

        Mock::given(method("GET"))
            .and(path("/api/v1/search/all"))
            .and(query_param("qbase64", &qbase64))
            .and(query_param("email", "test@example.com"))
            .and(query_param("key", "secret"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "results": [
                    ["https://target.example.com", "9.8.7.6"],
                    ["http://old.example.com", "1.1.1.1"]
                ]
            })))
            .mount(&server)
            .await;

        let scanner = FaviconHashScanner::with_params(
            reqwest::Client::new(),
            0,
            5,
            Some("test@example.com".to_string()),
            Some("secret".to_string()),
        ).with_base_urls(
            "https://api.shodan.io".to_string(),
            server.uri(), // fofa base url
        );
        let results = scanner.pivot_fofa(hash).await;
        assert_eq!(results.len(), 2, "FOFA pivot should return 2 matches");
        assert_eq!(results[0].host, "target.example.com");
        assert_eq!(results[0].metadata["source"], "fofa");
        assert_eq!(results[0].metadata["favicon_hash"], 54321);
        assert_eq!(results[0].metadata["ip"], "9.8.7.6");
        assert_eq!(results[1].host, "old.example.com");
    }

    #[tokio::test]
    async fn test_discover_no_favicon_returns_empty() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/favicon.ico"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let scanner = FaviconHashScanner::with_params(
            reqwest::Client::new(),
            0,
            0,
            None,
            None,
        );
        let uri = server.uri();
        let host = uri.trim_start_matches("http://");
        let target = TargetHost {
            host: host.to_string(),
            ..Default::default()
        };
        let results = scanner.discover(&target).await.unwrap();
        assert!(results.is_empty());
    }
}
