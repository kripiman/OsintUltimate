use reqwest::{Client, header::{HeaderMap, HeaderName, HeaderValue}};
use crate::models::TargetHost;
use anyhow::{Result, Context};
use std::time::Duration;

pub struct StealthClientBuilder;

impl StealthClientBuilder {
    pub fn build(target: &TargetHost, pm: &crate::utils::proxy::ProxyManager) -> Result<Client> {
        Self::create_builder(target, pm)?.build().context("Failed to build Stealth HTTP Client")
    }

    pub fn build_pinned(target: &TargetHost, pm: &crate::utils::proxy::ProxyManager, host: &str, addr: std::net::SocketAddr) -> Result<Client> {
        Self::create_builder(target, pm)?
            .resolve(host, addr)
            .build()
            .context("Failed to build Pinned Stealth HTTP Client")
    }

    fn create_builder(target: &TargetHost, pm: &crate::utils::proxy::ProxyManager) -> Result<reqwest::ClientBuilder> {
        let mut headers = HeaderMap::new();
        
        // 1. Extract tactical context
        let tc = &target.tactical_context;
        
        // 2. Determine User-Agent
        let ua = tc.get("user_agent")
            .and_then(|v| v.as_str())
            .unwrap_or(crate::utils::common::get_random_user_agent());
        
        headers.insert(reqwest::header::USER_AGENT, HeaderValue::from_str(ua)?);

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

        // 5. Build client with proxy if available
        let builder = Client::builder()
            .default_headers(headers)
            .timeout(Duration::from_secs(30))
            .danger_accept_invalid_certs(true); // Red teaming often needs this for internal/expired certs

        // 6. Mandatory Proxy Injection (Fail-Closed)
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
            ip: None,
            resolved_ip: None,
            status: TargetStatus::Pending,
            target_type: TargetType::Web,
            user: None,
            findings: Arc::new(Vec::new()),
            tool_suggestions: Arc::new(Vec::new()),
            tactical_context: Arc::new(serde_json::json!({
                "user_agent": "TacticalAgent/1.0",
                "headers": {
                    "X-Bypass": "True",
                    "X-Experimental": "1"
                }
            })),
            extra_data: Arc::new(serde_json::json!({})),
        };

        let pm = crate::utils::proxy::ProxyManager::new(Vec::new(), true);
        let _client = StealthClientBuilder::build(&target, &pm)?;
        Ok(())
    }
}
