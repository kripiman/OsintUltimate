use rand::Rng;
use std::collections::HashMap;
use std::time::Instant;

use crate::core::net_evasion::http_smuggle::Confidence;
use anyhow::Result;

/// Result of a Web Cache Deception probe.
#[derive(Debug, Clone)]
pub struct CacheDeceptionResult {
    pub vulnerable: bool,
    pub confidence: Confidence,
    pub cache_headers: HashMap<String, String>,
    pub response_time_ms: f64,
}

/// Configuration for the WCD probe.
#[derive(Debug, Clone, Default)]
pub struct CacheDeceptionConfig {
    pub session_cookie: Option<String>,
    pub sensitive_markers: Vec<String>,
}

/// Web Cache Deception probe.
pub struct CacheDeceptionProbe;

impl CacheDeceptionProbe {
    /// Probe `target:port` for Web Cache Deception.
    ///
    /// Sends two requests to the same cache-deception path
    /// (`base_path` + random suffix + `.css`).
    /// Request 1 populates the cache; request 2 confirms HIT.
    pub async fn probe(
        target: &str,
        port: u16,
        base_path: &str,
        config: &CacheDeceptionConfig,
    ) -> Result<CacheDeceptionResult> {
        let start = Instant::now();
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()?;

        let suffix: String = rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(8)
            .map(char::from)
            .collect();
        let path = Self::build_cache_path(base_path, &format!("{suffix}.css"));
        let url = format!("https://{target}:{port}{path}");

        // --- Request 1: populate cache ---
        let mut req1 = client.get(&url);
        if let Some(cookie) = &config.session_cookie {
            req1 = req1.header("Cookie", cookie);
        }
        let resp1 = req1.send().await?;
        let headers1 = Self::extract_cache_headers(&resp1);
        let _body1 = resp1.text().await.unwrap_or_default();

        // --- Request 2: confirm cache behaviour ---
        let mut req2 = client.get(&url);
        if let Some(cookie) = &config.session_cookie {
            req2 = req2.header("Cookie", cookie);
        }
        let resp2 = req2.send().await?;
        let headers2 = Self::extract_cache_headers(&resp2);
        let body2 = resp2.text().await.unwrap_or_default();

        let response_time_ms = start.elapsed().as_secs_f64() * 1000.0;

        // Determine cache confirmation
        let cache_confirmed = Self::cache_hit_confirmed(&headers1, &headers2);

        let (vulnerable, confidence) = if cache_confirmed {
            let has_sensitive = Self::body_contains_sensitive(&body2, &config.sensitive_markers);
            if has_sensitive {
                if config.session_cookie.is_some() {
                    (true, Confidence::Definite)
                } else {
                    (true, Confidence::Likely)
                }
            } else {
                (false, Confidence::Definite)
            }
        } else {
            (false, Confidence::Ambiguous)
        };

        let mut all_headers = headers1;
        all_headers.extend(headers2);

        Ok(CacheDeceptionResult {
            vulnerable,
            confidence,
            cache_headers: all_headers,
            response_time_ms,
        })
    }

    /// Build the cache-deception path from a base path and a file suffix.
    pub fn build_cache_path(base_path: &str, suffix: &str) -> String {
        let base = base_path.trim_end_matches('/');
        format!("{base}/{suffix}")
    }

    /// Extract cache-relevant headers from a response.
    fn extract_cache_headers(resp: &reqwest::Response) -> HashMap<String, String> {
        let mut map = HashMap::new();
        for key in ["x-cache", "cf-cache-status", "x-cache-hits", "age", "cache-control"] {
            if let Some(val) = resp.headers().get(key) {
                if let Ok(s) = val.to_str() {
                    map.insert(key.to_string(), s.to_string());
                }
            }
        }
        map
    }

    /// Determine whether the second request confirms cache behaviour.
    ///
    /// Checks for HIT indicators in req2 or an increase in `Age`.
    fn cache_hit_confirmed(
        h1: &HashMap<String, String>,
        h2: &HashMap<String, String>,
    ) -> bool {
        // Explicit HIT in req2
        if let Some(v) = h2.get("x-cache") {
            if v.to_ascii_uppercase().contains("HIT") {
                return true;
            }
        }
        if let Some(v) = h2.get("cf-cache-status") {
            if v.eq_ignore_ascii_case("HIT") {
                return true;
            }
        }
        if let Some(v) = h2.get("x-cache-hits") {
            if v.parse::<u64>().unwrap_or(0) > 0 {
                return true;
            }
        }
        // Age increased between req1 and req2
        let age1 = h1.get("age").and_then(|a| a.parse::<u64>().ok()).unwrap_or(0);
        let age2 = h2.get("age").and_then(|a| a.parse::<u64>().ok()).unwrap_or(0);
        if age2 > age1 {
            return true;
        }
        false
    }

    /// Check whether the response body contains any sensitive markers.
    fn body_contains_sensitive(body: &str, markers: &[String]) -> bool {
        let lower = body.to_lowercase();
        markers.iter().any(|m| lower.contains(&m.to_lowercase()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_cache_path() {
        assert_eq!(
            CacheDeceptionProbe::build_cache_path("/profile", "abc123.css"),
            "/profile/abc123.css"
        );
        assert_eq!(
            CacheDeceptionProbe::build_cache_path("/profile/", "abc123.css"),
            "/profile/abc123.css"
        );
        assert!(CacheDeceptionProbe::build_cache_path("/api", "xyz.css").ends_with(".css"));
    }

    #[tokio::test]
    async fn test_cache_deception_no_server() {
        let config = CacheDeceptionConfig::default();
        let result = CacheDeceptionProbe::probe("127.0.0.1", 59999, "/profile", &config).await;
        assert!(
            result.is_err(),
            "cache deception probe to nothing should fail: {:?}",
            result.ok()
        );
    }

    #[test]
    fn test_cache_hit_confirmed() {
        let mut h1 = HashMap::new();
        let mut h2 = HashMap::new();

        // No cache headers → not confirmed
        assert!(!CacheDeceptionProbe::cache_hit_confirmed(&h1, &h2));

        // X-Cache: HIT in req2
        h2.insert("x-cache".to_string(), "HIT".to_string());
        assert!(CacheDeceptionProbe::cache_hit_confirmed(&h1, &h2));

        // CF-Cache-Status: HIT
        h2.clear();
        h2.insert("cf-cache-status".to_string(), "HIT".to_string());
        assert!(CacheDeceptionProbe::cache_hit_confirmed(&h1, &h2));

        // Age increased
        h2.clear();
        h1.insert("age".to_string(), "0".to_string());
        h2.insert("age".to_string(), "5".to_string());
        assert!(CacheDeceptionProbe::cache_hit_confirmed(&h1, &h2));

        // Age same → not confirmed
        h2.insert("age".to_string(), "0".to_string());
        assert!(!CacheDeceptionProbe::cache_hit_confirmed(&h1, &h2));

        // X-Cache: MISS → not confirmed
        h1.clear();
        h2.clear();
        h2.insert("x-cache".to_string(), "MISS".to_string());
        assert!(!CacheDeceptionProbe::cache_hit_confirmed(&h1, &h2));
    }

    #[test]
    fn test_body_contains_sensitive() {
        let body = r#"{"username": "admin", "email": "a@b.com"}"#;
        let markers = vec!["username".to_string(), "password".to_string()];
        assert!(CacheDeceptionProbe::body_contains_sensitive(body, &markers));

        let body2 = "<html><body>Login</body></html>";
        assert!(!CacheDeceptionProbe::body_contains_sensitive(body2, &markers));
    }
}
