use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::{ResolverConfig, ResolverOpts, NameServerConfig, Protocol};
use tracing::debug;
use std::net::IpAddr;

/// Checks if a target is "live" by attempting to resolve its DNS record.
/// Returns Some(IP implementation check) if successful, None otherwise.
pub async fn is_target_live(target: &str) -> Option<IpAddr> {
    // Initial primitive check: Is it already an IP?
    if let Ok(ip) = target.parse::<IpAddr>() {
        return Some(ip);
    }

    // Construct a resolver
    // TODO: In a real high-perf scenario, we should pass a shared resolver ref
    // instead of creating one every time. But for now, let's create a shared one 
    // higher up or just bear the cost for clarity. 
    // Optimization: We will use a shared resolver if passed, but for this helper 
    // let's assume we want a quick check.
    
    // Better approach: Create a reusable resolver inside the Orchestrator or Main 
    // and pass it down. But to keep this function self-contained for now:
    let resolver = TokioAsyncResolver::tokio(
        ResolverConfig::google(),
        ResolverOpts::default(),
    );

    match resolver.lookup_ip(target).await {
        Ok(response) => {
            if let Some(ip) = response.iter().next() {
                debug!("Liveness check passed: {} -> {}", target, ip);
                return Some(ip);
            }
        }
        Err(e) => {
            debug!("Liveness check failed for {}: {}", target, e);
        }
    }
    
    None
}

/// Checks if an IP address is safe to scan (i.e., Global, not Private/Loopback).
/// Returns true if safe, false if it's a private/local/link-local address.
pub fn is_safe_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            // 127.0.0.0/8 (Loopback)
            if octets[0] == 127 { return false; }
            
            // 10.0.0.0/8 (Private)
            if octets[0] == 10 { return false; }
            
            // 172.16.0.0/12 (Private)
            if octets[0] == 172 && (octets[1] >= 16 && octets[1] <= 31) { return false; }
            
            // 192.168.0.0/16 (Private)
            if octets[0] == 192 && octets[1] == 168 { return false; }
            
            // 169.254.0.0/16 (Link-Local)
            if octets[0] == 169 && octets[1] == 254 { return false; }
            
            // 0.0.0.0/8 (Current network)
            if octets[0] == 0 { return false; }
            
            true
        },
        IpAddr::V6(ipv6) => {
            // ::1 (Loopback)
            if ipv6.is_loopback() { return false; }
            
            // fe80::/10 (Link-Local)
            // fc00::/7 (Unique Local)
            let segments = ipv6.segments();
            if (segments[0] & 0xffc0) == 0xfe80 { return false; }
            if (segments[0] & 0xfe00) == 0xfc00 { return false; }
            
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
    pub fn new(custom_resolvers: Option<Vec<String>>) -> Self {
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
        }

        Self {
            resolver: TokioAsyncResolver::tokio(
                router_config,
                resolver_opts,
            )
        }
    }

    pub async fn is_live(&self, target: &str) -> Option<IpAddr> {
        if let Ok(ip) = target.parse::<IpAddr>() {
            return Some(ip);
        }

        match self.resolver.lookup_ip(target).await {
            Ok(response) => {
                response.iter().next()
            }
            Err(_) => None
        }
    }
}
