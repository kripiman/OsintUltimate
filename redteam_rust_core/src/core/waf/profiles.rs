use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TlsProfile {
    Chrome126,
    Firefox128,
    Safari17,
    Curl,
    Custom(String),
}

impl TlsProfile {
    pub fn label(&self) -> &str {
        match self {
            TlsProfile::Chrome126 => "Chrome/126",
            TlsProfile::Firefox128 => "Firefox/128",
            TlsProfile::Safari17 => "Safari/17",
            TlsProfile::Curl => "curl/8.x",
            TlsProfile::Custom(s) => s.as_str(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpFingerprint {
    pub user_agent: String,
    pub accept_language: String,
    pub accept_encoding: String,
    pub custom_headers: HashMap<String, String>,
    pub tls_profile: TlsProfile,
    /// Jitter between consecutive requests (milliseconds)
    pub request_delay_ms: u64,
}

impl HttpFingerprint {
    /// Applies this fingerprint's headers to a reqwest::header::HeaderMap.
    pub fn apply_to_headers(&self) -> reqwest::header::HeaderMap {
        let mut headers = reqwest::header::HeaderMap::new();

        if let Ok(v) = reqwest::header::HeaderValue::from_str(&self.user_agent) {
            headers.insert(reqwest::header::USER_AGENT, v);
        }
        if !self.accept_language.is_empty() {
            if let Ok(v) = reqwest::header::HeaderValue::from_str(&self.accept_language) {
                headers.insert(reqwest::header::ACCEPT_LANGUAGE, v);
            }
        }
        if !self.accept_encoding.is_empty() {
            if let Ok(v) = reqwest::header::HeaderValue::from_str(&self.accept_encoding) {
                headers.insert(reqwest::header::ACCEPT_ENCODING, v);
            }
        }

        for (key, value) in &self.custom_headers {
            if let (Ok(k), Ok(v)) = (
                reqwest::header::HeaderName::from_bytes(key.as_bytes()),
                reqwest::header::HeaderValue::from_str(value),
            ) {
                headers.insert(k, v);
            }
        }

        headers
    }
}

/// Represents the mutated request configuration returned by the evasion engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MutatedRequest {
    pub fingerprint: Arc<HttpFingerprint>,
    pub strategy: super::policy::EvasionStrategy,
    /// If true, the caller should rebuild its reqwest::Client with new TLS config
    pub requires_tls_rebuild: bool,
    /// If true, the caller should route through a fresh ephemeral IP
    pub requires_new_ip: bool,
    /// Optional: AI-rewritten payload body
    pub rewritten_body: Option<String>,
    /// Optional: AI-rewritten URL path
    pub rewritten_path: Option<String>,
}

pub fn build_profile_pool() -> Vec<Arc<HttpFingerprint>> {
    let raw = vec![
        // Chrome on Windows 11
        HttpFingerprint {
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36".to_string(),
            accept_language: "en-US,en;q=0.9".to_string(),
            accept_encoding: "gzip, deflate, br, zstd".to_string(),
            custom_headers: HashMap::from([
                ("Sec-CH-UA".to_string(), "\"Chromium\";v=\"126\", \"Not;A=Brand\";v=\"24\", \"Google Chrome\";v=\"126\"".to_string()),
                ("Sec-CH-UA-Platform".to_string(), "\"Windows\"".to_string()),
                ("Sec-CH-UA-Mobile".to_string(), "?0".to_string()),
                ("Sec-Fetch-Dest".to_string(), "document".to_string()),
                ("Sec-Fetch-Mode".to_string(), "navigate".to_string()),
                ("Sec-Fetch-Site".to_string(), "none".to_string()),
                ("Sec-Fetch-User".to_string(), "?1".to_string()),
                ("Upgrade-Insecure-Requests".to_string(), "1".to_string()),
            ]),
            tls_profile: TlsProfile::Chrome126,
            request_delay_ms: 500,
        },
        // Firefox on Linux
        HttpFingerprint {
            user_agent: "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0".to_string(),
            accept_language: "en-US,en;q=0.5".to_string(),
            accept_encoding: "gzip, deflate, br".to_string(),
            custom_headers: HashMap::from([
                ("Sec-Fetch-Dest".to_string(), "document".to_string()),
                ("Sec-Fetch-Mode".to_string(), "navigate".to_string()),
                ("Sec-Fetch-Site".to_string(), "none".to_string()),
                ("Sec-Fetch-User".to_string(), "?1".to_string()),
                ("Upgrade-Insecure-Requests".to_string(), "1".to_string()),
                ("DNT".to_string(), "1".to_string()),
            ]),
            tls_profile: TlsProfile::Firefox128,
            request_delay_ms: 300,
        },
        // Safari on macOS
        HttpFingerprint {
            user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15".to_string(),
            accept_language: "en-US,en;q=0.9".to_string(),
            accept_encoding: "gzip, deflate, br".to_string(),
            custom_headers: HashMap::from([
                ("Sec-Fetch-Dest".to_string(), "document".to_string()),
                ("Sec-Fetch-Mode".to_string(), "navigate".to_string()),
                ("Sec-Fetch-Site".to_string(), "none".to_string()),
            ]),
            tls_profile: TlsProfile::Safari17,
            request_delay_ms: 700,
        },
        // Chrome on macOS
        HttpFingerprint {
            user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36".to_string(),
            accept_language: "en-GB,en;q=0.9,en-US;q=0.8".to_string(),
            accept_encoding: "gzip, deflate, br, zstd".to_string(),
            custom_headers: HashMap::from([
                ("Sec-CH-UA".to_string(), "\"Chromium\";v=\"126\", \"Google Chrome\";v=\"126\"".to_string()),
                ("Sec-CH-UA-Platform".to_string(), "\"macOS\"".to_string()),
                ("Sec-CH-UA-Mobile".to_string(), "?0".to_string()),
                ("Upgrade-Insecure-Requests".to_string(), "1".to_string()),
            ]),
            tls_profile: TlsProfile::Chrome126,
            request_delay_ms: 400,
        },
        // Edge on Windows
        HttpFingerprint {
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0".to_string(),
            accept_language: "en-US,en;q=0.9".to_string(),
            accept_encoding: "gzip, deflate, br, zstd".to_string(),
            custom_headers: HashMap::from([
                ("Sec-CH-UA".to_string(), "\"Microsoft Edge\";v=\"126\", \"Chromium\";v=\"126\"".to_string()),
                ("Sec-CH-UA-Platform".to_string(), "\"Windows\"".to_string()),
                ("Sec-CH-UA-Mobile".to_string(), "?0".to_string()),
            ]),
            tls_profile: TlsProfile::Chrome126,
            request_delay_ms: 350,
        },
        // Chrome on Android (mobile)
        HttpFingerprint {
            user_agent: "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.72 Mobile Safari/537.36".to_string(),
            accept_language: "en-US,en;q=0.9".to_string(),
            accept_encoding: "gzip, deflate, br".to_string(),
            custom_headers: HashMap::from([
                ("Sec-CH-UA-Mobile".to_string(), "?1".to_string()),
                ("Sec-CH-UA-Platform".to_string(), "\"Android\"".to_string()),
            ]),
            tls_profile: TlsProfile::Chrome126,
            request_delay_ms: 800,
        },
        // Firefox on Windows
        HttpFingerprint {
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0".to_string(),
            accept_language: "de-DE,de;q=0.9,en;q=0.5".to_string(),
            accept_encoding: "gzip, deflate, br".to_string(),
            custom_headers: HashMap::from([
                ("DNT".to_string(), "1".to_string()),
                ("Upgrade-Insecure-Requests".to_string(), "1".to_string()),
            ]),
            tls_profile: TlsProfile::Firefox128,
            request_delay_ms: 450,
        },
        // Googlebot (some WAFs whitelist crawlers)
        HttpFingerprint {
            user_agent: "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)".to_string(),
            accept_language: "*".to_string(),
            accept_encoding: "gzip, deflate".to_string(),
            custom_headers: HashMap::new(),
            tls_profile: TlsProfile::Curl,
            request_delay_ms: 2000,
        },
        // Curl-like minimal
        HttpFingerprint {
            user_agent: "curl/8.7.1".to_string(),
            accept_language: "".to_string(),
            accept_encoding: "gzip".to_string(),
            custom_headers: HashMap::new(),
            tls_profile: TlsProfile::Curl,
            request_delay_ms: 100,
        },
        // Safari on iOS
        HttpFingerprint {
            user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1".to_string(),
            accept_language: "es-419,es;q=0.9".to_string(),
            accept_encoding: "gzip, deflate, br".to_string(),
            custom_headers: HashMap::from([
                ("Sec-Fetch-Dest".to_string(), "document".to_string()),
                ("Sec-Fetch-Mode".to_string(), "navigate".to_string()),
            ]),
            tls_profile: TlsProfile::Safari17,
            request_delay_ms: 600,
        },
    ];
    raw.into_iter().map(Arc::new).collect()
}
