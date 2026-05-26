use super::SovereignReconScanner;
use serde::Deserialize;
use std::collections::HashSet;
use std::time::Duration;
use tracing::{debug, warn};
use crate::utils::api_budget::ApiBudgetRegistry;

const CACHE_TTL_SHORT_SECS: u64 = 43_200; // 12h
const CACHE_TTL_LONG_SECS: u64  = 86_400; // 24h

fn apply_cap(set: HashSet<String>, limit: usize) -> HashSet<String> {
    if limit == 0 { return HashSet::new(); }
    if set.len() > limit { set.into_iter().take(limit).collect() }
    else { set }
}

impl SovereignReconScanner {
    // --- Free Legitimate Phase 1.5a: crt.sh (Certificate Transparency) ---
    pub(super) async fn query_crtsh(&self, domain: &str) -> HashSet<String> {
        let limit = self.crtsh_max_hosts;
        if limit == 0 {
            return HashSet::new();
        }

        if let Some(cache) = crate::utils::api_cache::ApiCache::global() {
            if let Some(hit) = cache.get::<HashSet<String>>("crtsh", domain, "subdomains", Duration::from_secs(CACHE_TTL_SHORT_SECS)).await {
                return apply_cap(hit, limit);
            }
        }

        let mut subdomains = HashSet::new();
        debug!("🆓 Phase 1.5a: crt.sh certificate transparency for {}", domain);
        let url = format!("https://crt.sh/?q=%.{domain}&output=json");

        let mut success = false;
        if let Ok(client) = self.get_client("crt.sh").await {
            if let Ok(resp) = client.get(&url).send().await {
                #[derive(Deserialize)]
                struct CrtShEntry { name_value: Option<String> }
                if let Ok(data) = resp.json::<Vec<CrtShEntry>>().await {
                    success = true;
                    for entry in data {
                        if let Some(nv) = entry.name_value {
                            for line in nv.lines() {
                                let host = line.trim().to_lowercase();
                                if host.ends_with(domain) && !host.contains('*') {
                                    subdomains.insert(host);
                                }
                            }
                        }
                    }
                }
            }
        }

        if success {
            if let Some(cache) = crate::utils::api_cache::ApiCache::global() {
                cache.put("crtsh", domain, "subdomains", &subdomains).await;
            }
        }
        apply_cap(subdomains, limit)
    }

    // --- Free Legitimate Phase 1.5b: LeakIX (Leak Intelligence) ---
    pub(super) async fn query_leakix(&self, domain: &str) -> HashSet<String> {
        let limit = self.leakix_max_hosts;
        if limit == 0 {
            return HashSet::new();
        }

        if let Some(cache) = crate::utils::api_cache::ApiCache::global() {
            if let Some(hit) = cache.get::<HashSet<String>>("leakix", domain, "subdomains", Duration::from_secs(CACHE_TTL_SHORT_SECS)).await {
                return apply_cap(hit, limit);
            }
        }

        let url = format!("https://leakix.net/api/subdomains/{domain}");
        let subdomains = self.query_leakix_raw(domain, &url).await;

        if !subdomains.is_empty() {
            if let Some(cache) = crate::utils::api_cache::ApiCache::global() {
                cache.put("leakix", domain, "subdomains", &subdomains).await;
            }
        }
        apply_cap(subdomains, limit)
    }

    /// Internal: HTTP call + parse. Extracted for Wiremock testability.
    async fn query_leakix_raw(&self, domain: &str, url: &str) -> HashSet<String> {
        let mut subdomains = HashSet::new();
        debug!("🆓 Phase 1.5b: LeakIX leak intelligence for {}", domain);

        if let Ok(client) = self.get_client("leakix.net").await {
            let mut req = client.get(url).header("Accept", "application/json");
            if let Some(ref key) = self.leakix_key {
                if !key.is_empty() {
                    req = req.header("api-key", key);
                }
            }
            if let Ok(resp) = req.send().await {
                #[derive(Deserialize)]
                struct LeakIxSubdomain { subdomain: String }
                if let Ok(data) = resp.json::<Vec<LeakIxSubdomain>>().await {
                    for entry in data {
                        let host = entry.subdomain.to_lowercase();
                        if host.ends_with(domain) {
                            subdomains.insert(host);
                        }
                    }
                }
            }
        }

        subdomains
    }

    // --- Free Legitimate Phase 1.5c: GitHub Dorks (Secret/Hostname Leaks) ---
    pub(super) async fn query_github_dorks(&self, domain: &str) -> HashSet<String> {
        let limit = self.github_max_dorks;
        if limit == 0 {
            return HashSet::new();
        }

        if let Some(cache) = crate::utils::api_cache::ApiCache::global() {
            if let Some(hit) = cache.get::<HashSet<String>>("github_dorks", domain, "hostnames", Duration::from_secs(CACHE_TTL_LONG_SECS)).await {
                return apply_cap(hit, limit);
            }
        }

        let token = match &self.github_token {
            Some(t) if !t.is_empty() => t.clone(),
            _ => {
                warn!("GitHub dorks skipped: GITHUB_TOKEN not set.");
                return HashSet::new();
            }
        };

        if !ApiBudgetRegistry::get().can_spend("github", 1).await {
            return HashSet::new();
        }

        let mut hostnames = HashSet::new();
        debug!("🆓 Phase 1.5c: GitHub dork intelligence for {}", domain);

        let dorks = vec![
            format!("org:{} password", domain),
            format!("org:{} api_key", domain),
            format!("org:{} apikey", domain),
            format!("org:{} secret", domain),
            format!("{} password", domain),
            format!("{} api_key", domain),
        ];

        let client = match self.get_client("api.github.com").await {
            Ok(c) => c,
            Err(_) => return HashSet::new(),
        };

        let regex = match regex::Regex::new(&format!(r"([a-zA-Z0-9_-]+\.)+{}", regex::escape(domain))) {
            Ok(r) => r,
            Err(_) => return HashSet::new(),
        };

        let mut success = false;
        for dork in dorks.iter().take(limit) {
            let url = "https://api.github.com/search/code";
            match client.get(url)
                .query(&[("q", dork.as_str()), ("per_page", "10")])
                .header("Authorization", format!("token {}", token))
                .header("Accept", "application/vnd.github.v3.text-match+json")
                .send().await
            {
                Ok(resp) => {
                    if !resp.status().is_success() {
                        warn!("GitHub API error for dork '{}': HTTP {}", dork, resp.status());
                        continue;
                    }
                    #[derive(Deserialize)]
                    struct TextMatch { fragment: Option<String> }
                    #[derive(Deserialize)]
                    struct GitHubItem { text_matches: Option<Vec<TextMatch>> }
                    #[derive(Deserialize)]
                    struct GitHubResp { items: Option<Vec<GitHubItem>> }

                    if let Ok(data) = resp.json::<GitHubResp>().await {
                        success = true;
                        if let Some(items) = data.items {
                            for item in items {
                                if let Some(matches) = item.text_matches {
                                    for tm in matches {
                                        if let Some(fragment) = tm.fragment {
                                            for cap in regex.find_iter(&fragment) {
                                                let candidate = cap.as_str().to_lowercase();
                                                if !candidate.ends_with("github.com") && !candidate.ends_with("github.io") {
                                                    hostnames.insert(candidate);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!("GitHub request failed for dork '{}': {}", dork, e);
                }
            }
        }

        if success {
            if let Some(cache) = crate::utils::api_cache::ApiCache::global() {
                cache.put("github_dorks", domain, "hostnames", &hostnames).await;
            }
        }
        apply_cap(hostnames, limit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use crate::utils::config::Config;
    use crate::utils::proxy::ProxyManager;
    use wiremock::{MockServer, Mock, ResponseTemplate};
    use wiremock::matchers::{method, path};

    fn mock_proxy() -> Arc<ProxyManager> {
        Arc::new(ProxyManager::new(Vec::new(), false, crate::utils::config::ProxyMode::None, 1))
    }

    #[tokio::test]
    async fn test_crtsh_cap_zero_disables() {
        let mut config = Config::from_env();
        config.crtsh_max_hosts_per_scan = 0;
        let scanner = SovereignReconScanner::new(&config, mock_proxy());
        let result = scanner.query_crtsh("example.com").await;
        assert!(result.is_empty(), "crt.sh should be disabled when max_hosts == 0");
    }

    #[tokio::test]
    async fn test_leakix_cap_zero_disables() {
        let mut config = Config::from_env();
        config.leakix_max_hosts_per_scan = 0;
        let scanner = SovereignReconScanner::new(&config, mock_proxy());
        let result = scanner.query_leakix("example.com").await;
        assert!(result.is_empty(), "LeakIX should be disabled when max_hosts == 0");
    }

    #[tokio::test]
    async fn test_github_dorks_cap_zero_disables() {
        let mut config = Config::from_env();
        config.github_max_dorks_per_scan = 0;
        let scanner = SovereignReconScanner::new(&config, mock_proxy());
        let result = scanner.query_github_dorks("example.com").await;
        assert!(result.is_empty(), "GitHub dorks should be disabled when max_dorks == 0");
    }

    // ─── LeakIX Wiremock tests (Defect 3 regression) ─────────────────────────

    #[tokio::test]
    async fn test_leakix_subdomains_parses_fqdn() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/subdomains/example.com"))
            .respond_with(ResponseTemplate::new(200)
                .set_body_json(serde_json::json!([
                    {"subdomain": "www.example.com", "distinct_ips": 1, "last_seen": "2023-01-20T11:25:41.243Z"},
                    {"subdomain": "api.example.com", "distinct_ips": 2, "last_seen": "2023-02-15T08:12:00.000Z"}
                ])))
            .mount(&server)
            .await;

        let mut config = Config::from_env();
        config.leakix_max_hosts_per_scan = 50;
        let scanner = SovereignReconScanner::new(&config, mock_proxy());
        let url = format!("{}/api/subdomains/example.com", server.uri());
        let result = scanner.query_leakix_raw("example.com", &url).await;

        assert_eq!(result.len(), 2);
        assert!(result.contains("www.example.com"));
        assert!(result.contains("api.example.com"));
    }

    #[tokio::test]
    async fn test_leakix_empty_array() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/subdomains/example.com"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(&server)
            .await;

        let mut config = Config::from_env();
        config.leakix_max_hosts_per_scan = 50;
        let scanner = SovereignReconScanner::new(&config, mock_proxy());
        let url = format!("{}/api/subdomains/example.com", server.uri());
        let result = scanner.query_leakix_raw("example.com", &url).await;

        assert!(result.is_empty(), "Empty array should yield empty HashSet");
    }

    #[tokio::test]
    async fn test_leakix_429_rate_limit() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/subdomains/example.com"))
            .respond_with(ResponseTemplate::new(429)
                .insert_header("x-limited-for", "344.24ms"))
            .mount(&server)
            .await;

        let mut config = Config::from_env();
        config.leakix_max_hosts_per_scan = 50;
        let scanner = SovereignReconScanner::new(&config, mock_proxy());
        let url = format!("{}/api/subdomains/example.com", server.uri());
        let result = scanner.query_leakix_raw("example.com", &url).await;

        assert!(result.is_empty(), "429 should gracefully degrade to empty HashSet");
    }

    #[tokio::test]
    async fn test_leakix_old_schema_fails_silently() {
        let server = MockServer::start().await;
        // Simulate the old /domain endpoint schema that caused silent failure
        Mock::given(method("GET"))
            .and(path("/api/subdomains/example.com"))
            .respond_with(ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
                    "Services": [{"host": "www.example.com", "ip": "1.2.3.4"}],
                    "Leaks": null
                })))
            .mount(&server)
            .await;

        let mut config = Config::from_env();
        config.leakix_max_hosts_per_scan = 50;
        let scanner = SovereignReconScanner::new(&config, mock_proxy());
        let url = format!("{}/api/subdomains/example.com", server.uri());
        let result = scanner.query_leakix_raw("example.com", &url).await;

        assert!(result.is_empty(), "Old /domain schema should fail to parse and return empty (no panic)");
    }
}
