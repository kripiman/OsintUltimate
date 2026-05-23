use super::SovereignReconScanner;
use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use serde::Deserialize;
use std::collections::HashSet;
use std::time::Duration;
use tracing::{debug, warn};
use crate::utils::api_budget::ApiBudgetRegistry;
use crate::utils::shodan_keyring::ShodanKeyring;

const CACHE_TTL_SHORT_SECS: u64 = 43_200; // 12h: free/rate-limited APIs
const CACHE_TTL_LONG_SECS: u64  = 86_400; // 24h: paid APIs with quota cost

fn apply_cap(set: HashSet<String>, limit: usize) -> HashSet<String> {
    if limit == 0 { return HashSet::new(); }
    if set.len() > limit { set.into_iter().take(limit).collect() }
    else { set }
}

impl SovereignReconScanner {
    // --- Phase 0: Wayback Machine (URL History) ---
    pub(super) async fn query_wayback(&self, domain: &str) -> HashSet<String> {
        if let Some(cache) = crate::utils::api_cache::ApiCache::global() {
            if let Some(hit) = cache.get::<HashSet<String>>("wayback", domain, "subdomains", Duration::from_secs(CACHE_TTL_SHORT_SECS)).await {
                return hit;
            }
        }

        let mut subdomains = HashSet::new();
        debug!("🕰️ Phase 0: Wayback Machine historical URL discovery for {}", domain);
        let url = format!("http://web.archive.org/cdx/search/cdx?url=*.{}/*&output=json&collapse=urlkey&fl=original", domain);
        
        let mut success = false;
        if let Ok(client) = self.get_client("web.archive.org").await {
            if let Ok(resp) = client.get(&url).send().await {
                if let Ok(data) = resp.json::<Vec<Vec<String>>>().await {
                    success = true;
                    for entry in data.into_iter().skip(1) { // Skip header
                        if let Some(target_url) = entry.first() {
                            if let Ok(parsed) = url::Url::parse(target_url) {
                                if let Some(host) = parsed.host_str() {
                                    if host.ends_with(domain) {
                                        subdomains.insert(host.to_string());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        if success {
            if let Some(cache) = crate::utils::api_cache::ApiCache::global() {
                cache.put("wayback", domain, "subdomains", &subdomains).await;
            }
        }
        subdomains
    }

    // --- Phase 0.5: HackerTarget ---
    pub(super) async fn query_hackertarget(&self, domain: &str) -> HashSet<String> {
        if let Some(cache) = crate::utils::api_cache::ApiCache::global() {
            if let Some(hit) = cache.get::<HashSet<String>>("hackertarget", domain, "subdomains", Duration::from_secs(CACHE_TTL_SHORT_SECS)).await {
                return hit;
            }
        }

        let mut subdomains = HashSet::new();
        debug!("🎯 Phase 0.5: HackerTarget host search for {}", domain);
        let url = format!("https://api.hackertarget.com/hostsearch/?q={}", domain);
        
        let mut success = false;
        if let Ok(client) = self.get_client("api.hackertarget.com").await {
            if let Ok(resp) = client.get(&url).send().await {
                if let Ok(text) = resp.text().await {
                    success = true;
                    for line in text.lines() {
                        let parts: Vec<&str> = line.split(',').collect();
                        if let Some(host) = parts.first() {
                            if host.ends_with(domain) {
                                subdomains.insert(host.to_string());
                            }
                        }
                    }
                }
            }
        }

        if success {
            if let Some(cache) = crate::utils::api_cache::ApiCache::global() {
                cache.put("hackertarget", domain, "subdomains", &subdomains).await;
            }
        }
        subdomains
    }

    // --- Phase 1: Chaos (PD) ---
    pub(super) async fn query_chaos(&self, domain: &str) -> HashSet<String> {
        if let Some(cache) = crate::utils::api_cache::ApiCache::global() {
            if let Some(hit) = cache.get::<HashSet<String>>("chaos", domain, "subdomains", Duration::from_secs(CACHE_TTL_SHORT_SECS)).await {
                return hit;
            }
        }

        let mut subdomains = HashSet::new();
        let key = match &self.chaos_key {
            Some(k) if !k.is_empty() => k,
            _ => return subdomains,
        };

        if !ApiBudgetRegistry::get().can_spend("chaos", 1).await {
            return subdomains;
        }

        debug!("🚀 Phase 1: Chaos strike for {}", domain);
        let url = format!("https://chaos.projectdiscovery.io/v1/domains/{}/subdomains", domain);
        
        let mut success = false;
        if let Ok(client) = self.get_client("chaos.projectdiscovery.io").await {
            if let Ok(resp) = client.get(&url).header("Authorization", key).send().await {
                #[derive(Deserialize)]
                struct ChaosResp { subdomains: Option<Vec<String>> }
                if let Ok(data) = resp.json::<ChaosResp>().await {
                    success = true;
                    if let Some(subs) = data.subdomains {
                        for s in subs { subdomains.insert(format!("{}.{}", s, domain)); }
                    }
                }
            }
        }

        if success {
            if let Some(cache) = crate::utils::api_cache::ApiCache::global() {
                cache.put("chaos", domain, "subdomains", &subdomains).await;
            }
        }
        subdomains
    }

    // --- Phase 2: SecurityTrails ---
    pub(super) async fn query_securitytrails(&self, domain: &str) -> HashSet<String> {
        let limit = self.securitytrails_max_hosts;
        if limit == 0 {
            return HashSet::new();
        }

        if let Some(cache) = crate::utils::api_cache::ApiCache::global() {
            if let Some(hit) = cache.get::<HashSet<String>>("securitytrails", domain, "subdomains", Duration::from_secs(CACHE_TTL_LONG_SECS)).await {
                return apply_cap(hit, limit);
            }
        }

        let mut subdomains = HashSet::new();
        let key = match &self.sectrails_key {
            Some(k) if !k.is_empty() => k,
            _ => return subdomains,
        };

        if !ApiBudgetRegistry::get().can_spend("securitytrails", 1).await {
            return subdomains;
        }

        debug!("🛰️ Phase 2: SecurityTrails mapping for {}", domain);
        let url = format!("https://api.securitytrails.com/v1/domain/{}/subdomains", domain);
        
        let mut success = false;
        if let Ok(client) = self.get_client("api.securitytrails.com").await {
            if let Ok(resp) = client.get(&url).header("APIKEY", key).send().await {
                #[derive(Deserialize)]
                struct STResp { subdomains: Option<Vec<String>> }
                if let Ok(data) = resp.json::<STResp>().await {
                    success = true;
                    if let Some(subs) = data.subdomains {
                        for s in subs { subdomains.insert(format!("{}.{}", s, domain)); }
                    }
                }
            }
        }

        if success {
            if let Some(cache) = crate::utils::api_cache::ApiCache::global() {
                cache.put("securitytrails", domain, "subdomains", &subdomains).await;
            }
        }
        apply_cap(subdomains, limit)
    }

    // --- Phase 3: Netlas (Paid & Optimized) ---
    pub(super) async fn query_netlas(&self, domain: &str) -> HashSet<String> {
        if let Some(cache) = crate::utils::api_cache::ApiCache::global() {
            if let Some(hit) = cache.get::<HashSet<String>>("netlas", domain, "subdomains", Duration::from_secs(CACHE_TTL_LONG_SECS)).await {
                return hit;
            }
        }

        let mut subdomains = HashSet::new();
        let key = match &self.netlas_key {
            Some(k) if !k.is_empty() => k,
            _ => return subdomains,
        };

        if !ApiBudgetRegistry::get().can_spend("netlas", 1).await {
            return subdomains;
        }

        debug!("💎 Phase 3: Netlas High-Precision Deep Dive for {}", domain);
        let query = format!("domain:*.{}", domain);
        let url = format!("https://app.netlas.io/api/v1/responses/?q={}", urlencoding::encode(&query));
        
        let mut success = false;
        if let Ok(client) = self.get_client("app.netlas.io").await {
            if let Ok(resp) = client.get(&url).header("X-API-Key", key).send().await {
                #[derive(Deserialize)]
                struct NetlasItem { data: Option<NetlasData> }
                #[derive(Deserialize)]
                struct NetlasData { domain: Option<String> }
                #[derive(Deserialize)]
                struct NetlasResp { items: Option<Vec<NetlasItem>> }
                
                if let Ok(data) = resp.json::<NetlasResp>().await {
                    success = true;
                    if let Some(items) = data.items {
                        for item in items {
                            if let Some(d) = item.data.and_then(|x| x.domain) {
                                subdomains.insert(d);
                            }
                        }
                    }
                }
            }
        }

        if success {
            if let Some(cache) = crate::utils::api_cache::ApiCache::global() {
                cache.put("netlas", domain, "subdomains", &subdomains).await;
            }
        }
        subdomains
    }

    // --- Phase 4a: Shodan DNS (student key — /dns/domain/) ---
    async fn query_shodan_dns(&self, domain: &str) -> HashSet<String> {
        let limit = self.shodan_host_ip_max_hosts;
        if limit == 0 { return HashSet::new(); }

        if let Some(cache) = crate::utils::api_cache::ApiCache::global() {
            if let Some(hit) = cache.get::<HashSet<String>>("shodan_dns", domain, "subdomains", Duration::from_secs(CACHE_TTL_LONG_SECS)).await {
                return apply_cap(hit, limit);
            }
        }

        let mut results = HashSet::new();
        let (key, slot) = match ShodanKeyring::get().get_key_with_slot_for_dns() {
            Some((k, s)) => (k, s),
            _ => return results,
        };
        if !ApiBudgetRegistry::get().can_spend(slot, 1).await { return results; }

        debug!("🔭 Phase 4a: Shodan DNS subdomain discovery for {}", domain);
        let url = format!("https://api.shodan.io/dns/domain/{}", domain);
        let mut success = false;
        if let Ok(client) = self.get_client("api.shodan.io").await {
            if let Ok(resp) = client.get(&url).query(&[("key", key)]).send().await {
                #[derive(Deserialize)]
                struct ShodanDnsResp { subdomains: Option<Vec<String>> }
                if let Ok(data) = resp.json::<ShodanDnsResp>().await {
                    success = true;
                    if let Some(subs) = data.subdomains {
                        for s in subs { results.insert(format!("{}.{}", s, domain)); }
                    }
                }
            }
        }
        if success {
            if let Some(cache) = crate::utils::api_cache::ApiCache::global() {
                cache.put("shodan_dns", domain, "subdomains", &results).await;
            }
        }
        apply_cap(results, limit)
    }

    // --- Phase 4b: Shodan Search (paid/membership key — /shodan/host/search) ---
    async fn query_shodan_search(&self, domain: &str) -> HashSet<String> {
        let limit = self.shodan_paid_max_hosts;
        if limit == 0 { return HashSet::new(); }

        if let Some(cache) = crate::utils::api_cache::ApiCache::global() {
            if let Some(hit) = cache.get::<HashSet<String>>("shodan_search", domain, "subdomains", Duration::from_secs(CACHE_TTL_LONG_SECS)).await {
                return apply_cap(hit, limit);
            }
        }

        let mut results = HashSet::new();
        let key = match ShodanKeyring::get().get_key_for_search() {
            Some(k) => k,
            _ => return results,
        };
        if !ApiBudgetRegistry::get().can_spend("shodan_paid", 1).await { return results; }

        debug!("🔭 Phase 4b: Shodan paid search for hostname:{}", domain);
        let query = format!("hostname:{}", domain);
        let url = "https://api.shodan.io/shodan/host/search";
        let mut success = false;
        if let Ok(client) = self.get_client("api.shodan.io").await {
            if let Ok(resp) = client.get(url)
                .query(&[("key", key), ("query", query.as_str()), ("minify", "true")])
                .send().await
            {
                #[derive(Deserialize)]
                struct ShodanMatch { hostnames: Option<Vec<String>> }
                #[derive(Deserialize)]
                struct ShodanSearchResp { matches: Option<Vec<ShodanMatch>> }
                if let Ok(data) = resp.json::<ShodanSearchResp>().await {
                    success = true;
                    if let Some(matches) = data.matches {
                        for m in matches {
                            if let Some(hosts) = m.hostnames {
                                for h in hosts { results.insert(h); }
                            }
                        }
                    }
                }
            }
        }
        if success {
            if let Some(cache) = crate::utils::api_cache::ApiCache::global() {
                cache.put("shodan_search", domain, "subdomains", &results).await;
            }
        }
        apply_cap(results, limit)
    }

    // --- Phase 4: Shodan (union of DNS + Search) ---
    pub(super) async fn query_shodan(&self, domain: &str) -> HashSet<String> {
        let mut results = self.query_shodan_dns(domain).await;
        results.extend(self.query_shodan_search(domain).await);
        let combined_limit = std::cmp::min(self.shodan_host_ip_max_hosts, self.shodan_paid_max_hosts);
        apply_cap(results, combined_limit)
    }

    // --- Phase 5: Crimina    // --- Phase 5: Criminal IP (Reputation) ---
    pub(super) async fn query_criminalip(&self, host: &str) -> Vec<String> {
        if let Some(cache) = crate::utils::api_cache::ApiCache::global() {
            if let Some(hit) = cache.get::<Vec<String>>("criminalip", host, "reputation", Duration::from_secs(CACHE_TTL_LONG_SECS)).await {
                return hit;
            }
        }

        let mut findings = Vec::new();
        let key = match &self.criminalip_key {
            Some(k) if !k.is_empty() => k,
            _ => return findings,
        };

        if !ApiBudgetRegistry::get().can_spend("criminalip", 1).await {
            return findings;
        }

        debug!("🏴‍☠️ Phase 5: Criminal IP reputation scoring for {}", host);
        let url = format!("https://api.criminalip.io/v1/asset/search?query={}", urlencoding::encode(host));
        
        let mut success = false;
        if let Ok(client) = self.get_client("api.criminalip.io").await {
            if let Ok(resp) = client.get(&url)
                .header("x-api-key", key)
                .header("User-Agent", "Sentinel/1.0")
                .send().await {
                
                #[derive(Deserialize)]
                struct CIPResp { score: Option<CIPScore> }
                #[derive(Deserialize)]
                struct CIPScore { inbound: Option<u32>, _outbound: Option<u32> }
                
                if let Ok(data) = resp.json::<CIPResp>().await {
                    success = true;
                    if let Some(score) = data.score {
                        if score.inbound.unwrap_or(0) > 3 {
                            findings.push(format!("CRIMINALIP: {} has suspicious inbound reputation score", host));
                        }
                    }
                }
            }
        }

        if success {
            if let Some(cache) = crate::utils::api_cache::ApiCache::global() {
                cache.put("criminalip", host, "reputation", &findings).await;
            }
        }
        findings
    }

    // --- Phase 6: FOFA (High Coverage) ---
    pub(super) async fn query_fofa(&self, domain: &str) -> HashSet<String> {
        let limit = self.fofa_max_hosts;
        if limit == 0 {
            return HashSet::new();
        }

        if let Some(cache) = crate::utils::api_cache::ApiCache::global() {
            if let Some(hit) = cache.get::<HashSet<String>>("fofa", domain, "subdomains", Duration::from_secs(CACHE_TTL_LONG_SECS)).await {
                return apply_cap(hit, limit);
            }
        }

        let mut subdomains = HashSet::new();
        let (email, key) = match (&self.fofa_email, &self.fofa_key) {
            (Some(e), Some(k)) if !e.is_empty() && !k.is_empty() => (e, k),
            _ => return subdomains,
        };

        if !ApiBudgetRegistry::get().can_spend("fofa", 1).await {
            return subdomains;
        }

        debug!("🌍 Phase 6: FOFA global asset discovery for {}", domain);
        let query = format!("domain=\"{}\"", domain);
        let qbase64 = URL_SAFE.encode(query);
        
        let mut page = 1;
        let max_pages = 5;
        let page_size = 1000;
        let mut success = false;
        
        loop {
            let url = format!("https://fofa.info/api/v1/search/all?email={}&key={}&qbase64={}&fields=host&size={}&page={}", 
                email, key, qbase64, page_size, page);
            
            match self.get_client("fofa.info").await {
                Ok(client) => match client.get(&url).send().await {
                    Ok(resp) => {
                        if !resp.status().is_success() {
                            warn!("⚠️ FOFA API error at page {}: HTTP {}", page, resp.status());
                            break;
                        }
                        #[derive(Deserialize)]
                        struct FofaResp { results: Option<Vec<Vec<String>>>, total: Option<usize> }
                        match resp.json::<FofaResp>().await {
                            Ok(data) => {
                                success = true;
                                if let Some(results) = data.results {
                                    let count = results.len();
                                    for row in results {
                                        if let Some(host) = row.first() {
                                            let clean_host = host.replace("http://", "").replace("https://", "");
                                            subdomains.insert(clean_host);
                                        }
                                    }
                                    
                                    let total = data.total.unwrap_or(0);
                                    let total_pages = total.div_ceil(page_size);
                                    
                                    if count < page_size || page >= total_pages || page >= max_pages {
                                        break;
                                    }
                                } else {
                                    break;
                                }
                            }
                            Err(e) => {
                                warn!("⚠️ FOFA JSON parse error at page {}: {}", page, e);
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        warn!("⚠️ FOFA request failure at page {}: {}", page, e);
                        break;
                    }
                },
                Err(e) => {
                    warn!("⚠️ FOFA client creation failure: {}", e);
                    break;
                }
            }
            page += 1;
            self.jitter.sleep().await;
        }

        if success {
            if let Some(cache) = crate::utils::api_cache::ApiCache::global() {
                cache.put("fofa", domain, "subdomains", &subdomains).await;
            }
        }
        apply_cap(subdomains, limit)
    }

    // --- Phase 7: ZoomEye (Network Context) ---
    pub(super) async fn query_zoomeye(&self, domain: &str) -> HashSet<String> {
        if let Some(cache) = crate::utils::api_cache::ApiCache::global() {
            if let Some(hit) = cache.get::<HashSet<String>>("zoomeye", domain, "subdomains", Duration::from_secs(CACHE_TTL_LONG_SECS)).await {
                return hit;
            }
        }

        let mut subdomains = HashSet::new();
        let key = match &self.zoomeye_key {
            Some(k) if !k.is_empty() => k,
            _ => return subdomains,
        };

        if !ApiBudgetRegistry::get().can_spend("zoomeye", 1).await {
            return subdomains;
        }

        debug!("👁️ Phase 7: ZoomEye network context discovery for {}", domain);
        
        let mut page = 1;
        let max_pages = 10;
        let page_size = 20;
        let mut success = false;
        
        loop {
            let url = format!("https://api.zoomeye.org/web/search?query=site:{}&page={}", domain, page);
            
            match self.get_client("api.zoomeye.org").await {
                Ok(client) => match client.get(&url).header("API-KEY", key).send().await {
                    Ok(resp) => {
                        if !resp.status().is_success() {
                            warn!("⚠️ ZoomEye API error at page {}: HTTP {}", page, resp.status());
                            break;
                        }
                        #[derive(Deserialize)]
                        struct ZoomEyeMatch { site: Option<String> }
                        #[derive(Deserialize)]
                        struct ZoomEyeResp { matches: Option<Vec<ZoomEyeMatch>>, total: Option<usize> }
                        match resp.json::<ZoomEyeResp>().await {
                            Ok(data) => {
                                success = true;
                                if let Some(matches) = data.matches {
                                    let count = matches.len();
                                    if count == 0 { break; }
                                    for m in matches {
                                        if let Some(site) = m.site {
                                            subdomains.insert(site);
                                        }
                                    }
                                    
                                    let total = data.total.unwrap_or(0);
                                    let total_pages = total.div_ceil(page_size);
 
                                    if count < page_size || page >= total_pages || page >= max_pages {
                                        break;
                                    }
                                } else {
                                    break;
                                }
                            }
                            Err(e) => {
                                warn!("⚠️ ZoomEye JSON parse error at page {}: {}", page, e);
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        warn!("⚠️ ZoomEye request failure at page {}: {}", page, e);
                        break;
                    }
                },
                Err(e) => {
                    warn!("⚠️ ZoomEye client creation failure: {}", e);
                    break;
                }
            }
            page += 1;
            self.jitter.sleep().await;
        }

        if success {
            if let Some(cache) = crate::utils::api_cache::ApiCache::global() {
                cache.put("zoomeye", domain, "subdomains", &subdomains).await;
            }
        }
        subdomains
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::Arc;
    use crate::utils::config::Config;
    use crate::utils::proxy::ProxyManager;

    #[test]
    fn test_per_api_cap_truncates_at_limit() {
        let input: HashSet<String> = (0..10).map(|i| i.to_string()).collect();
        assert_eq!(apply_cap(input.clone(), 3).len(), 3);
        assert_eq!(apply_cap(input.clone(), 5).len(), 5);
        assert_eq!(apply_cap(input, 15).len(), 10);
    }

    #[test]
    fn test_per_api_cap_propagation() {
        let mut config = Config::from_env();
        config.securitytrails_max_hosts_per_scan = 10;
        config.fofa_max_hosts_per_scan = 20;
        config.shodan_host_ip_max_hosts_per_scan = 30;
        config.shodan_paid_max_hosts_per_scan = 40;

        let pm = Arc::new(ProxyManager::new(Vec::new(), false, crate::utils::config::ProxyMode::None, 1));
        let scanner = SovereignReconScanner::new(&config, pm);

        assert_eq!(scanner.securitytrails_max_hosts, 10);
        assert_eq!(scanner.fofa_max_hosts, 20);
        assert_eq!(scanner.shodan_host_ip_max_hosts, 30);
        assert_eq!(scanner.shodan_paid_max_hosts, 40);
    }

    #[tokio::test]
    async fn test_per_api_cap_respects_zero_disables() {
        let mut config = Config::from_env();
        config.securitytrails_max_hosts_per_scan = 0;
        config.fofa_max_hosts_per_scan = 0;
        config.shodan_host_ip_max_hosts_per_scan = 0;
        config.shodan_paid_max_hosts_per_scan = 0;

        let pm = Arc::new(ProxyManager::new(Vec::new(), false, crate::utils::config::ProxyMode::None, 1));
        let scanner = SovereignReconScanner::new(&config, pm);

        // SecurityTrails
        let st = scanner.query_securitytrails("example.com").await;
        assert!(st.is_empty(), "SecurityTrails should be disabled");

        // FOFA
        let fofa = scanner.query_fofa("example.com").await;
        assert!(fofa.is_empty(), "FOFA should be disabled");

        // Shodan
        let shodan = scanner.query_shodan("example.com").await;
        assert!(shodan.is_empty(), "Shodan should be disabled");
    }
}
