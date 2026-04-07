use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::{ResolverConfig, ResolverOpts, NameServerConfig, Protocol};
use std::net::IpAddr;

/// Checks if a target is "live" using a shared resolver.
/// Removed self-contained version to prevent re-creating DNS resolvers (P2).
pub async fn is_target_live(checker: &LivenessChecker, target: &str) -> Option<IpAddr> {
    checker.is_live(target).await
}

/// Validates whether a given host is safe from SSRF attacks.
pub fn is_ssrf_safe_host(host: &str) -> bool {
    if host.is_empty() { return false; }
    let host_lower = host.to_lowercase();
    
    // 1. Strict blacklist for cloud metadata and internal names
    let name_blacklist = ["localhost", "broadcasthost", "local", "invalid", "kubernetes.default.svc", "metadata.google.internal", "169.254.169.254"];
    if name_blacklist.iter().any(|&b| host_lower.contains(b)) {
        return false;
    }

    // 2. Exact IP parsing
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return is_safe_ip(&ip);
    }

    // 3. Decimal IP representation (e.g. 2130706433 -> 127.0.0.1)
    if host.chars().all(|c| c.is_digit(10)) {
        if let Ok(val) = host.parse::<u32>() {
            return is_safe_ip(&std::net::Ipv4Addr::from(val).into());
        }
    }
    
    // 4. Hexadecimal/Octal heuristics bypass
    if host_lower.starts_with("0x") || (host_lower.starts_with("0") && host.chars().all(|c| c.is_digit(8))) {
         return false; // Safely drop obscured encodings lacking exact DNS matching
    }
    
    // 5. Encoded string bypasses
    if host.chars().any(|c| c == '%' || c == '\\') { return false; }
    
    true
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
            
            true
        }
    }
}

/// Batch liveness checker using a shared resolver for performance
#[derive(Clone)]
pub struct LivenessChecker {
    resolver: TokioAsyncResolver,
}

impl LivenessChecker {
    pub fn new(custom_resolvers: Option<Vec<String>>, doh: bool) -> Self {
        let resolver_opts = ResolverOpts::default();
        let mut router_config = ResolverConfig::google();

        if let Some(servers) = custom_resolvers {
             let mut name_servers = Vec::new();
             for ip_str in servers {
                 if let Ok(ip) = ip_str.parse::<std::net::IpAddr>() {
                      let socket_addr = std::net::SocketAddr::new(ip, 53);
                      name_servers.push(NameServerConfig::new(socket_addr, Protocol::Udp));
                      name_servers.push(NameServerConfig::new(socket_addr, Protocol::Tcp));
                 }
             }
             if !name_servers.is_empty() {
                 router_config = ResolverConfig::from_parts(None, vec![], name_servers);
             }
        } else if doh {
             // P1 FIX: Use DNS over HTTPS (DoH) for encrypted requests
             router_config = ResolverConfig::google_https();
             // Note: Depending on hickory version, there might be TLS requirements.
             // If this fails to compile, we may need to enable "webpki-roots" or "native-certs" features in Cargo.toml for hickory-resolver.
        }

        let resolver = hickory_resolver::TokioAsyncResolver::tokio(router_config, resolver_opts);

        Self {
            resolver
        }
    }

    pub async fn is_live(&self, target: &str) -> Option<IpAddr> {
        if let Ok(ip) = target.parse::<IpAddr>() {
            if is_safe_ip(&ip) {
                return Some(ip);
            } else {
                return None;
            }
        }

        match self.resolver.lookup_ip(target).await {
            Ok(response) => {
                for ip in response.iter() {
                    if is_safe_ip(&ip) {
                        return Some(ip);
                    }
                }
                None
            }
            Err(_) => None
        }
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
}
