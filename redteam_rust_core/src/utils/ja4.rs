use tls_parser::{TlsMessage, TlsMessageHandshake, TlsExtensionType, parse_tls_extensions, TlsExtension};
use anyhow::Result;
use sha2::{Sha256, Digest};

/// Calculates a JA4 fingerprint from raw ClientHello bytes.
/// Format: [t|q][Version][SNI][ALPN][ExtCount][CipherCount]_[CipherHash]_[ExtHash]
pub fn calculate_ja4(bytes: &[u8]) -> Result<String> {
    let (_, packet) = tls_parser::parse_tls_plaintext(bytes)
        .map_err(|_| anyhow::anyhow!("Failed to parse TLS packet"))?;
    
    for msg in packet.msg {
        if let TlsMessage::Handshake(TlsMessageHandshake::ClientHello(hello)) = msg {
            // 1. Version (b)
            let protocol = match hello.version.0 {
                0x0304 => "13",
                0x0303 => "12",
                0x0302 => "11",
                0x0301 => "10",
                _ => "00",
            };
            
            // 2. SNI (c) & ALPN (d)
            let mut sni_type = "x";
            let mut alpn_prefix = "00";
            
            let parsed_exts = hello.ext
                .and_then(|raw| parse_tls_extensions(raw).ok().map(|(_, e)| e))
                .unwrap_or_default();

            for ext in &parsed_exts {
                match ext {
                    TlsExtension::SNI(_) => {
                        sni_type = "d"; // Simplified: assumes domain if SNI exists
                    },
                    TlsExtension::ALPN(alpn) => {
                        if let Some(first) = alpn.first() {
                            if first.len() >= 2 {
                                if let Ok(s) = std::str::from_utf8(&first[..2]) {
                                    alpn_prefix = s;
                                }
                            }
                        }
                    },
                    _ => {}
                }
            }
            
            // 3. Counts (e, f)
            let ext_count = format!("{:02}", parsed_exts.len().min(99));
            let cipher_count = format!("{:02}", hello.ciphers.len().min(99));
            
            let ja4_a = format!("t{}{}{}{}{}", protocol, sni_type, alpn_prefix, ext_count, cipher_count);

            // 4. JA4_b: Cipher Suites Hash (Sorted, excluding GREASE)
            let mut ciphers: Vec<u16> = hello.ciphers.iter()
                .map(|c| c.0)
                .filter(|&c| !is_grease(c))
                .collect();
            ciphers.sort_unstable();
            let ciphers_str = ciphers.iter().map(|&c| format!("{:04x}", c)).collect::<Vec<_>>().join(",");
            let ja4_b = &hash_string(&ciphers_str)[..12];

            // 5. JA4_c: Extensions Hash (Sorted, excluding GREASE/SNI/ALPN)
            let mut exts: Vec<u16> = parsed_exts.iter()
                .map(|e| TlsExtensionType::from(e).0)
                .filter(|&e| !is_grease(e) && e != 0 && e != 16) // 0=SNI, 16=ALPN
                .collect();
            exts.sort_unstable();
            let exts_str = exts.iter().map(|&e| format!("{:04x}", e)).collect::<Vec<_>>().join(",");
            let ja4_c = &hash_string(&exts_str)[..12];

            return Ok(format!("{}_{}_{}", ja4_a, ja4_b, ja4_c));
        }
    }
    
    anyhow::bail!("No ClientHello found in bytes")
}

/// Calculates a JA4H fingerprint from HTTP request metadata.
/// Format: [Method][Version][Cookie][Referer][HeaderCount][Lang]_[HeaderHash]_[CookieHash]_[CookieValueHash]
pub fn calculate_ja4h(
    method: &str,
    version: &str,
    headers: &[(String, String)],
    cookies: &[(String, String)],
    lang: Option<&str>,
) -> Result<String> {
    // 1. JA4H_a
    let method_part = method.to_lowercase();
    let method_code = &method_part[..method_part.len().min(2)];
    
    let version_code = match version {
        "HTTP/1.0" => "10",
        "HTTP/1.1" => "11",
        "HTTP/2.0" | "H2" | "HTTP/2" => "20",
        _ => "11",
    };
    
    let has_cookie = if !cookies.is_empty() { "c" } else { "n" };
    let has_referer = if headers.iter().any(|(k, _)| k.to_lowercase() == "referer") { "r" } else { "n" };
    
    let filtered_headers: Vec<String> = headers.iter()
        .map(|(k, _)| k.to_lowercase())
        .filter(|k| !k.starts_with(':') && k != "cookie" && k != "referer" && !k.is_empty())
        .collect();
    
    let header_count = format!("{:02}", filtered_headers.len().min(99));
    
    let lang_code = if let Some(l) = lang {
        let l_clean = l.replace('-', "").replace(';', ",").to_lowercase();
        let first = l_clean.split(',').next().unwrap_or("0000");
        let truncated = &first[..first.len().min(4)];
        format!("{}{}", truncated, "0".repeat(4 - truncated.len()))
    } else {
        "0000".to_string()
    };
    
    let ja4h_a = format!("{}{}{}{}{}{}", method_code, version_code, has_cookie, has_referer, header_count, lang_code);
    
    // 2. JA4H_b: Header Hash (Original order, filtered)
    let ja4h_b = if !filtered_headers.is_empty() {
        &hash_string(&filtered_headers.join(","))[..12]
    } else {
        "000000000000"
    };
    
    // 3. JA4H_c: Cookie Name Hash (Sorted)
    // 4. JA4H_d: Cookie Value Hash (Sorted by Name)
    let (ja4h_c, ja4h_d) = if !cookies.is_empty() {
        let mut sorted_cookies = cookies.to_vec();
        sorted_cookies.sort_by(|a, b| a.0.cmp(&b.0));
        
        let names: Vec<String> = sorted_cookies.iter().map(|(k, _)| k.clone()).collect();
        let values: Vec<String> = sorted_cookies.iter().map(|(_, v)| v.clone()).collect();
        
        (&hash_string(&names.join(","))[..12], &hash_string(&values.join(","))[..12])
    } else {
        ("000000000000", "000000000000")
    };
    
    Ok(format!("{}_{}_{}_{}", ja4h_a, ja4h_b, ja4h_c, ja4h_d))
}

/// Calculates a JA4S fingerprint from raw ServerHello bytes.
/// Format: [t|q][Version][ExtCount][ALPN]_[Cipher]_[ExtHash]
pub fn calculate_ja4s(bytes: &[u8]) -> Result<String> {
    let (_, packet) = tls_parser::parse_tls_plaintext(bytes)
        .map_err(|_| anyhow::anyhow!("Failed to parse TLS packet"))?;
    
    for msg in packet.msg {
        if let TlsMessage::Handshake(TlsMessageHandshake::ServerHello(hello)) = msg {
            // 1. Version
            let protocol = match hello.version.0 {
                0x0304 => "13",
                0x0303 => "12",
                0x0302 => "11",
                0x0301 => "10",
                _ => "00",
            };
            
            // 2. ALPN
            let mut alpn_code = "00".to_string();
            let parsed_exts = hello.ext
                .and_then(|raw| parse_tls_extensions(raw).ok().map(|(_, e)| e))
                .unwrap_or_default();

            for ext in &parsed_exts {
                if let TlsExtension::ALPN(alpn) = ext {
                    if let Some(first) = alpn.first() {
                        if first.len() >= 2 {
                            if let Ok(s) = std::str::from_utf8(&first[..2]) {
                                alpn_code = s.to_string();
                            } else {
                                alpn_code = "99".to_string();
                            }
                        }
                    }
                }
            }
            
            // 3. Ext Count
            let ext_count = format!("{:02}", parsed_exts.len().min(99));
            
            let ja4s_a = format!("t{}{}{}", protocol, ext_count, alpn_code);

            // 4. JA4S_b: Cipher (Single, selected)
            let ja4s_b = format!("{:04x}", hello.cipher.0);

            // 5. JA4S_c: Extensions Hash (Original order, excluding GREASE)
            let exts: Vec<u16> = parsed_exts.iter()
                .map(|e| TlsExtensionType::from(e).0)
                .filter(|&e| !is_grease(e))
                .collect();
            let exts_str = exts.iter().map(|&e| format!("{:04x}", e)).collect::<Vec<_>>().join(",");
            let ja4s_c = &hash_string(&exts_str)[..12];

            return Ok(format!("{}_{}_{}", ja4s_a, ja4s_b, ja4s_c));
        }
    }
    
    anyhow::bail!("No ServerHello found in bytes")
}

fn is_grease(val: u16) -> bool {
    let lo = (val & 0xff) as u8;
    lo == (val >> 8) as u8 && (lo & 0x0f) == 0x0a
}

fn hash_string(s: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ja4h_calculation() {
        let headers = vec![
            ("User-Agent".to_string(), "Mozilla/5.0".to_string()),
            ("Accept".to_string(), "*/*".to_string()),
            ("Referer".to_string(), "https://google.com".to_string()),
        ];
        let cookies = vec![
            ("session".to_string(), "secret".to_string()),
            ("user".to_string(), "admin".to_string()),
        ];
        
        let ja4h = calculate_ja4h("GET", "HTTP/1.1", &headers, &cookies, Some("en-US,en;q=0.9")).unwrap();
        
        // ge11cr02enus...
        assert!(ja4h.starts_with("ge11cr02enus"));
        assert_eq!(ja4h.split('_').count(), 4);
    }
}
