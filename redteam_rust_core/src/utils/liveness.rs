use std::net::IpAddr;
use tracing::{warn, info};
use std::sync::Arc;
use crate::utils::proxy::ProxyManager;
use anyhow::{Result, Context};

/// Checks if a target is "live" using a shared resolver.
/// Removed self-contained version to prevent re-creating DNS resolvers (P2).
pub async fn is_target_live(checker: &LivenessChecker, target: &str) -> Option<IpAddr> {
    checker.is_live(target).await
}

/// Checks if an IP address is safe to scan (i.e., Global, not Private/Loopback).
/// Returns true if safe, false if it's a private/local/link-local address.
pub fn is_safe_ip(ip: &IpAddr) -> bool {
    // V10 FIX (HIGH-002): Comprehensive SSRF RFC checks.
    // The previous implementation missed several unroutable metadata/CGNAT ranges.
    match ip {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            if ipv4.is_private() || ipv4.is_loopback() || ipv4.is_link_local() 
                || ipv4.is_broadcast() || ipv4.is_documentation() || ipv4.is_unspecified() || ipv4.is_multicast() { 
                return false; 
            }
            // 100.64.0.0/10 CGNAT (Missing in stable Rust is_global, heavily used by cloud metadata)
            if octets[0] == 100 && (octets[1] >= 64 && octets[1] <= 127) { return false; }
            // 192.0.0.0/24 IETF Protocol Assignments
            if octets[0] == 192 && octets[1] == 0 && octets[2] == 0 { return false; }
            // 198.18.0.0/15 Benchmarking
            if octets[0] == 198 && (octets[1] == 18 || octets[1] == 19) { return false; }
            // 0.0.0.0/8 Current network
            if octets[0] == 0 { return false; }
            
            // AUDIT-002 FIX: Additional restricted IPv4 ranges
            // 198.51.100.0/24 TEST-NET-2
            if octets[0] == 198 && octets[1] == 51 && octets[2] == 100 { return false; }
            // 203.0.113.0/24 TEST-NET-3
            if octets[0] == 203 && octets[1] == 0 && octets[2] == 113 { return false; }
            // 240.0.0.0/4 Reserved (including 255.255.255.255)
            if octets[0] >= 240 { return false; }
            // 169.254.0.0/16 Link-Local (Explicit check)
            if octets[0] == 169 && octets[1] == 254 { return false; }

            true
        },
        IpAddr::V6(ipv6) => {
            // Block loopback and unspecified
            if ipv6.is_loopback() || ipv6.is_unspecified() { return false; }
            if let Some(mapped_v4) = ipv6.to_ipv4_mapped() { return is_safe_ip(&IpAddr::V4(mapped_v4)); }
            
            // fe80::/10 (Link-Local)
            // fc00::/7 (Unique Local)
            let segments = ipv6.segments();
            if (segments[0] & 0xffc0) == 0xfe80 { return false; }
            if (segments[0] & 0xfe00) == 0xfc00 { return false; }

            // AUDIT-002 FIX: Missing restricted IPv6 ranges
            // 2001:db8::/32 (Documentation)
            if segments[0] == 0x2001 && segments[1] == 0x0db8 { return false; }
            // 2001:10::/28 (ORCHIDv2)
            if segments[0] == 0x2001 && (segments[1] & 0xfff0) == 0x0010 { return false; }
            // 2002::/16 (6to4)
            if segments[0] == 0x2002 { return false; }
            // ff00::/8 (Multicast)
            if (segments[0] & 0xff00) == 0xff00 { return false; }
            // 100::/64 (Discard-only)
            if segments[0] == 0x0100 && segments[1] == 0 && segments[2] == 0 && segments[3] == 0 { return false; }
            
            true
        }
    }
}

/// V12 HARDENING: Centralized SSRF check for hostnames or IPs.
pub async fn is_ssrf_safe_host(target: &str) -> bool {
    if let Ok(ip) = target.parse::<IpAddr>() {
        return is_safe_ip(&ip);
    }
    // Reject unresolved hostnames by default; only pre-resolved IPs are permitted for network operations.
    false
}

/// Batch liveness checker using a shared resolver for performance
#[derive(Clone)]
pub struct LivenessChecker {
    resolver: Arc<hickory_resolver::TokioAsyncResolver>,
    proxy_manager: Option<Arc<ProxyManager>>,
}

impl LivenessChecker {
    pub fn new(custom_resolvers: Option<Vec<String>>, doh: bool) -> Self {
        Self::new_with_proxy(custom_resolvers, doh, None)
    }

    pub fn new_with_proxy(custom_resolvers: Option<Vec<String>>, doh: bool, pm: Option<Arc<ProxyManager>>) -> Self {
        let resolver_opts = hickory_resolver::config::ResolverOpts::default();
        let mut router_config = hickory_resolver::config::ResolverConfig::google();

        if let Some(servers) = custom_resolvers {
             let mut name_servers = Vec::new();
             for ip_str in servers {
                 if let Ok(ip) = ip_str.parse::<std::net::IpAddr>() {
                      let socket_addr = std::net::SocketAddr::new(ip, 53);
                      name_servers.push(hickory_resolver::config::NameServerConfig::new(socket_addr, hickory_resolver::config::Protocol::Udp));
                      name_servers.push(hickory_resolver::config::NameServerConfig::new(socket_addr, hickory_resolver::config::Protocol::Tcp));
                 }
             }
             if !name_servers.is_empty() {
                 router_config = hickory_resolver::config::ResolverConfig::from_parts(None, vec![], name_servers);
             }
        } else if doh {
             router_config = hickory_resolver::config::ResolverConfig::google_https();
        }

        let resolver = hickory_resolver::TokioAsyncResolver::tokio(router_config, resolver_opts);

        Self {
            resolver: Arc::new(resolver),
            proxy_manager: pm,
        }
    }

    pub async fn is_live(&self, target: &str) -> Option<IpAddr> {
        if let Ok(ip) = target.parse::<IpAddr>() {
            if is_safe_ip(&ip) {
                return Some(ip);
            } else {
                warn!("🚫 LIVENESS: Blocked attempt to scan unsafe IP: {}", ip);
                return None;
            }
        }

        // V13: Mandatory proxied DNS in stealth mode
        if let Some(ref pm) = self.proxy_manager {
            if !pm.is_empty() {
                return match self.proxied_lookup(target, pm).await {
                    Ok(ip) => Some(ip),
                    Err(e) => {
                        warn!("⚠️ V13: Proxied DNS lookup failed for {}: {}", target, e);
                        None
                    }
                };
            }
        }

        match self.resolver.lookup_ip(target).await {
            Ok(response) => {
                for ip in response.iter() {
                    if is_safe_ip(&ip) {
                        return Some(ip);
                    } else {
                        warn!("🚫 LIVENESS: Resolved unsafe IP {} for host {}, skipping.", ip, target);
                    }
                }
                None
            }
            Err(_) => None
        }
    }

    /// V13: Performs a DNS lookup through a SOCKS5 proxy using Google DoH API.
    /// This ensures 100% isolation as the request is an encrypted HTTP call routed through the SOCKS tunnel.
    async fn proxied_lookup(&self, target: &str, pm: &ProxyManager) -> Result<IpAddr> {
        // We use Google's JSON DoH API as it's the easiest to route through a standard reqwest client.
        // Step 1: Get a proxied client pinned to dns.google (8.8.8.8)
        let dns_host = "dns.google";
        let (_, client) = pm.get_client_fail_closed(dns_host)?;
        
        // Step 2: Query the DoH API
        let url = format!("https://{}/resolve?name={}&type=A", dns_host, target);
        info!("🛡️ V13: Routing stealth DNS query for {} through SOCKS5 DoH...", target);
        
        let resp = client.get(url)
            .header("Host", dns_host)
            .send().await
            .context("Stealth DoH request failed")?;
        
        let json: serde_json::Value = resp.json().await.context("Invalid DoH response JSON")?;
        
        // Parse the answer
        if let Some(answers) = json["Answer"].as_array() {
            for answer in answers {
                if let Some(data) = answer["data"].as_str() {
                    if let Ok(ip) = data.parse::<IpAddr>() {
                        if is_safe_ip(&ip) {
                            return Ok(ip);
                        }
                    }
                }
            }
        }
        
        anyhow::bail!("No safe IP addresses found for host {} via stealth DoH", target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_safe_ip_v4() {
        assert!(is_safe_ip(&"8.8.8.8".parse().unwrap()));
        assert!(!is_safe_ip(&"127.0.0.1".parse().unwrap()));
        assert!(!is_safe_ip(&"10.0.0.1".parse().unwrap()));
        assert!(!is_safe_ip(&"100.64.0.1".parse().unwrap())); // CGNAT
    }

    #[test]
    fn test_is_safe_ip_v6() {
        // Safe global
        assert!(is_safe_ip(&"2001:4860:4860::8888".parse().unwrap()));
        
        // Loopback/Unspecified
        assert!(!is_safe_ip(&"::1".parse().unwrap()));
        assert!(!is_safe_ip(&"::".parse().unwrap()));
        
        // Link-Local
        assert!(!is_safe_ip(&"fe80::1".parse().unwrap()));
        
        // Unique-Local
        assert!(!is_safe_ip(&"fc00::1".parse().unwrap()));
        
        // AUDIT-002: Restricted ranges
        assert!(!is_safe_ip(&"2001:db8::1".parse().unwrap())); // Documentation
        assert!(!is_safe_ip(&"2001:10::1".parse().unwrap()));  // ORCHIDv2
        assert!(!is_safe_ip(&"2002::1".parse().unwrap()));    // 6to4
    }

    #[test]
    fn test_is_ssrf_safe_host_rejects_hostnames() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Failed to create tokio runtime");

        runtime.block_on(async {
            assert!(!is_ssrf_safe_host("example.com").await);
            assert!(is_ssrf_safe_host("8.8.8.8").await);
        });
    }
}
