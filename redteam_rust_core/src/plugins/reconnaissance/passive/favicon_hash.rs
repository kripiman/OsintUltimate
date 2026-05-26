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
const SHODAN_API_TIMEOUT_SECS: u64 = 15;
const FOFA_API_TIMEOUT_SECS: u64 = 15;

pub struct FaviconHashScanner {
    client: reqwest::Client,
    shodan_max_hosts: usize,
    fofa_max_hosts: usize,
    fofa_email: Option<String>,
    fofa_key: Option<String>,
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
                .unwrap_or_else(|_| reqwest::Client::new()),
            shodan_max_hosts: config.shodan_paid_max_hosts_per_scan,
            fofa_max_hosts: config.fofa_max_hosts_per_scan,
            fofa_email: config.fofa_email,
            fofa_key: config.fofa_api_key,
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
        }
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
        let url = "https://api.shodan.io/shodan/host/search";
        let client = match reqwest::Client::builder()
            .timeout(Duration::from_secs(SHODAN_API_TIMEOUT_SECS))
            .build()
        {
            Ok(c) => c,
            Err(_) => reqwest::Client::new(),
        };

        let mut discovered = Vec::new();
        if let Ok(resp) = client
            .get(url)
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
        let url = format!(
            "https://fofa.info/api/v1/search/all?email={}&key={}&qbase64={}&fields=host,ip&size={}&page=1",
            email, key, qbase64, self.fofa_max_hosts.min(1000)
        );
        let client = match reqwest::Client::builder()
            .timeout(Duration::from_secs(FOFA_API_TIMEOUT_SECS))
            .build()
        {
            Ok(c) => c,
            Err(_) => reqwest::Client::new(),
        };

        let mut discovered = Vec::new();
        if let Ok(resp) = client.get(&url).send().await {
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
            poc_mode: true,
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
        let server = MockServer::start().await;
        let hash = 12345i32;

        // ShodanKeyring must be initialized for check_dependencies, but pivot_shodan
        // reads it at runtime. We'll test via mocking the HTTP response path by
        // injecting a custom client... except pivot_shodan creates its own client.
        // To avoid relying on the global keyring, we test the max_hosts gate directly.
        let scanner = FaviconHashScanner::with_params(
            reqwest::Client::new(),
            0, // max_hosts = 0 disables Shodan
            0,
            None,
            None,
        );
        let results = scanner.pivot_shodan(hash).await;
        assert!(results.is_empty(), "Shodan pivot should be disabled when max_hosts=0");
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
