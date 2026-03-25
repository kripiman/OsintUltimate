use reqwest::{Client, header::{HeaderMap, HeaderName, HeaderValue}};
use crate::models::TargetHost;
use anyhow::{Result, Context};
use std::time::Duration;

pub struct StealthClientBuilder;

impl StealthClientBuilder {
    pub fn build(target: &TargetHost) -> Result<Client> {
        Self::create_builder(target)?.build().context("Failed to build Stealth HTTP Client")
    }

    pub fn build_pinned(target: &TargetHost, host: &str, addr: std::net::SocketAddr) -> Result<Client> {
        Self::create_builder(target)?
            .resolve(host, addr)
            .build()
            .context("Failed to build Pinned Stealth HTTP Client")
    }

    fn create_builder(target: &TargetHost) -> Result<reqwest::ClientBuilder> {
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

        Ok(builder)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{TargetHost, TargetStatus, TargetType};

    #[test]
    fn test_stealth_client_headers() -> Result<()> {
        let target = TargetHost {
            host: "test.com".to_string(),
            ip: None,
            status: TargetStatus::Pending,
            target_type: TargetType::Web,
            findings: Vec::new(),
            tool_suggestions: Vec::new(),
            tactical_context: serde_json::json!({
                "user_agent": "TacticalAgent/1.0",
                "headers": {
                    "X-Bypass": "True",
                    "X-Experimental": "1"
                }
            }),
            extra_data: serde_json::json!({}),
        };

        let _client = StealthClientBuilder::build(&target)?;
        Ok(())
    }
}
