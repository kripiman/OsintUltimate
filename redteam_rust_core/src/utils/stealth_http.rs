use reqwest::{Client, header::{HeaderMap, HeaderName, HeaderValue}};
use crate::models::TargetHost;
use anyhow::{Result, Context};
use std::time::Duration;
use crate::utils::proxy::ProxyManager;

pub struct StealthClientBuilder;

impl StealthClientBuilder {
    pub fn build(target: &TargetHost, pm: &ProxyManager) -> Result<Client> {
        Self::create_builder(target, pm, &crate::plugins::detection_evasion::stealth_policy::StealthPolicy::default())?.build().context("Failed to build Stealth HTTP Client")
    }

    pub fn build_with_policy(target: &TargetHost, pm: &ProxyManager, policy: &crate::plugins::detection_evasion::stealth_policy::StealthPolicy) -> Result<Client> {
        Self::create_builder(target, pm, policy)?.build().context("Failed to build Policy-driven Stealth HTTP Client")
    }

    pub fn build_pinned(target: &TargetHost, pm: &ProxyManager, host: &str, addr: std::net::SocketAddr) -> Result<Client> {
        Self::create_builder(target, pm, &crate::plugins::detection_evasion::stealth_policy::StealthPolicy::default())?
            .resolve(host, addr)
            .build()
            .context("Failed to build Pinned Stealth HTTP Client")
    }

    pub fn build_pinned_infra(pm: &ProxyManager, host: &str, addr: std::net::SocketAddr) -> Result<Client> {
        Self::create_builder_infra(pm, &crate::plugins::detection_evasion::stealth_policy::StealthPolicy::default())?
            .resolve(host, addr)
            .build()
            .context("Failed to build Pinned Stealth Infrastructure Client")
    }

    fn create_builder_infra(pm: &ProxyManager, policy: &crate::plugins::detection_evasion::stealth_policy::StealthPolicy) -> Result<reqwest::ClientBuilder> {
        let mut headers = HeaderMap::new();
        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36";
        headers.insert(reqwest::header::USER_AGENT, HeaderValue::from_str(ua)?);
        
        headers.entry(reqwest::header::ACCEPT).or_insert(HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"));
        headers.entry(reqwest::header::ACCEPT_LANGUAGE).or_insert(HeaderValue::from_static("en-US,en;q=0.9"));

        let mut builder = Client::builder()
            .default_headers(headers)
            .timeout(Duration::from_secs(30))
            .danger_accept_invalid_certs(true);

        if policy.ja3_spoofing {
            builder = builder.use_rustls_tls(); 
        }
        
        pm.configure_client_builder(builder)
    }

    fn create_builder(target: &TargetHost, pm: &ProxyManager, policy: &crate::plugins::detection_evasion::stealth_policy::StealthPolicy) -> Result<reqwest::ClientBuilder> {
        let mut headers = HeaderMap::new();
        
        // 1. Extract tactical context
        let tc = &target.tactical_context;
        
        // 2. Determine User-Agent with Rotation support
        let ua = if policy.user_agent_rotation {
            crate::utils::common::get_random_user_agent().to_string()
        } else {
            tc.get("user_agent")
                .and_then(|v| v.as_str())
                .unwrap_or("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36")
                .to_string()
        };
        
        headers.insert(reqwest::header::USER_AGENT, HeaderValue::from_str(&ua)?);

        // 3. Add custom tactical headers (e.g., bypass headers)
        if let Some(custom_headers) = tc.get("headers").and_then(|h| h.as_object()) {
            for (k, v) in custom_headers {
                if let Some(val_str) = v.as_str() {
                    if let Ok(h_name) = HeaderName::from_bytes(k.as_bytes()) {
                        if let Ok(h_val) = HeaderValue::from_str(val_str) {
                            headers.insert(h_name, h_val);
                        }
                    }
                }
            }
        }

        // 4. Default modern browser headers if not present
        headers.entry(reqwest::header::ACCEPT).or_insert(HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"));
        headers.entry(reqwest::header::ACCEPT_LANGUAGE).or_insert(HeaderValue::from_static("en-US,en;q=0.9"));
        headers.entry(reqwest::header::CACHE_CONTROL).or_insert(HeaderValue::from_static("max-age=0"));

        // 5. Build client with basic evasion
        let mut builder = Client::builder()
            .default_headers(headers)
            .timeout(Duration::from_secs(30))
            .danger_accept_invalid_certs(true);

        // 6. Evasion Hardening (V14.2 Professional)
        if policy.ja3_spoofing {
            builder = builder.use_rustls_tls(); 
        }
        
        if policy.http2_priority_manipulation {
            builder = builder.http2_initial_stream_window_size(65535);
        }

        if !policy.follow_redirects {
            builder = builder.redirect(reqwest::redirect::Policy::none());
        }

        // 7. Mandatory Proxy Injection (Fail-Closed)
        pm.configure_client_builder(builder)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{TargetHost, TargetStatus, TargetType};
    use std::sync::Arc;

    #[test]
    fn test_stealth_client_headers() -> Result<()> {
        let target = TargetHost {
            host: "test.com".to_string(),
            target_type: TargetType::Web,
            tactical_context: Arc::new(serde_json::json!({
                "user_agent": "TacticalAgent/1.0",
                "headers": {
                    "X-Bypass": "True",
                    "X-Experimental": "1"
                }
            })),
            ..Default::default()
        };

        let pm = ProxyManager::new(Vec::new(), true, crate::utils::config::ProxyMode::Dante, 0);
        let _client = StealthClientBuilder::build(&target, &pm)?;
        Ok(())
    }
}
