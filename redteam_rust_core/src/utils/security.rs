use once_cell::sync::Lazy;
use regex::Regex;

pub fn validate_target(target: &str) -> bool {
    if target.is_empty() || target.starts_with('-') {
        return false;
    }

    // 1. Valid as IP Address (v4 or v6)
    if target.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }

    // 2. Valid as URL
    if target.contains("://") {
        if let Ok(url) = url::Url::parse(target) {
            return url.host_str().is_some();
        }
    }

    // 3. Valid as Hostname
    static HOSTNAME_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"^(?i)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$").unwrap()
    });
    HOSTNAME_RE.is_match(target)
}

pub async fn is_ssrf_safe_host_async(host: &str) -> bool {
    if host.is_empty() { return false; }
    
    // 1. Resolve host to IPs
    match tokio::net::lookup_host(format!("{}:80", host)).await {
        Ok(addrs) => {
            for addr in addrs {
                if !is_ip_safe(addr.ip()) {
                    tracing::warn!("🛡️ SSRF BLOCK: Resolved IP {} for host {} is NOT safe.", addr.ip(), host);
                    return false;
                }
            }
        },
        Err(e) => {
            // If it doesn't resolve as a hostname, check if it's already an IP
            if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                if !is_ip_safe(ip) { return false; }
            } else if host.chars().all(|c| c.is_ascii_digit()) {
                 if let Ok(val) = host.parse::<u32>() {
                    let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::from(val));
                    if !is_ip_safe(ip) { return false; }
                }
            } else {
                tracing::debug!("SSRF check: host {} did not resolve: {}", host, e);
            }
        }
    }

    // 2. Extra string-based checks
    let host_lower = host.to_lowercase();
    let name_blacklist = ["localhost", "broadcasthost", "local", "invalid"];
    if name_blacklist.iter().any(|&b| host_lower == b) {
        return false;
    }

    true
}

fn is_ip_safe(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let bytes = v4.octets();
            !(bytes[0] == 127 || bytes[0] == 10 || bytes[0] == 0 ||
              (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) ||
              (bytes[0] == 192 && bytes[1] == 168) ||
              (bytes[0] == 169 && bytes[1] == 254) ||
              (bytes[0] == 100 && (bytes[1] >= 64 && bytes[1] <= 127)) ||
              (bytes[0] == 198 && (bytes[1] == 18 || bytes[1] == 19)) || // Benchmarking
              (bytes[0] == 198 && bytes[1] == 51 && bytes[2] == 100) || // TEST-NET-2
              (bytes[0] == 203 && bytes[1] == 0 && bytes[2] == 113) || // TEST-NET-3
              (bytes[0] >= 240)) // Reserved
        },
        std::net::IpAddr::V6(v6) => {
            if v6.is_loopback() || v6.is_unspecified() { return false; }
            let segments = v6.segments();
            if (segments[0] & 0xffc0) == 0xfe80 { return false; } // Link Local
            if (segments[0] & 0xfe00) == 0xfc00 { return false; } // Unique Local
            if segments[0] == 0x2001 && segments[1] == 0x0db8 { return false; } // Doc
            if (segments[0] & 0xff00) == 0xff00 { return false; } // Multicast
            if segments[0] == 0x0100 && segments[1] == 0 && segments[2] == 0 && segments[3] == 0 { return false; } // Discard
            
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_ip_safe(std::net::IpAddr::V4(v4));
            }
            true
        }
    }
}

pub fn is_ssrf_safe_host(host: &str) -> bool {
    if host.is_empty() { return false; }
    
    // Sync version (Legacy/Blocking fallback) - NO DNS resolution to avoid thread starvation
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return is_ip_safe(ip);
    }
    
    if host.chars().all(|c| c.is_ascii_digit()) {
        if let Ok(val) = host.parse::<u32>() {
            return is_ip_safe(std::net::IpAddr::V4(std::net::Ipv4Addr::from(val)));
        }
    }

    let host_lower = host.to_lowercase();
    let name_blacklist = ["localhost", "broadcasthost", "local", "invalid"];
    if name_blacklist.iter().any(|&b| host_lower == b) {
        return false;
    }

    true
}

pub fn build_ssrf_safe_client() -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            let url = attempt.url();
            if let Some(host) = url.host_str() {
                if is_ssrf_safe_host(host) {
                    attempt.follow()
                } else {
                    attempt.stop()
                }
            } else {
                attempt.stop()
            }
        }))
        .build()
}

pub async fn validate_url_ssrf(url_str: &str) -> anyhow::Result<()> {
    let url = url::Url::parse(url_str)
        .map_err(|_| anyhow::anyhow!("Invalid URL: {}", url_str))?;
    
    if let Some(host) = url.host_str() {
        if !is_ssrf_safe_host_async(host).await {
            return Err(anyhow::anyhow!("SSRF violation: Host '{}' resolves to a private or loopback IP address.", host));
        }
    } else {
        return Err(anyhow::anyhow!("URL has no host: {}", url_str));
    }
    
    Ok(())
}
