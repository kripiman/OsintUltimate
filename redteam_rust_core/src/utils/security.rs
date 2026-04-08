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

pub fn is_ssrf_safe_host(host: &str) -> bool {
    if host.is_empty() { return false; }
    let host_lower = host.to_lowercase();
    
    // Exact name blacklist
    let name_blacklist = ["localhost", "broadcasthost", "local", "invalid"];
    if name_blacklist.iter().any(|&b| host_lower == b) {
        return false;
    }

    // Direct IP parse
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return match ip {
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
                    return is_ssrf_safe_host(&v4.to_string());
                }
                true
            }
        };
    }

    // Decimal IP representation
    if host.chars().all(|c| c.is_digit(10)) {
        if let Ok(val) = host.parse::<u32>() {
            return is_ssrf_safe_host(&std::net::Ipv4Addr::from(val).to_string());
        }
    }

    true
}
