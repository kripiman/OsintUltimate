use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use crate::models::TargetHost;
use anyhow::{Result, Context};
use std::time::Duration;
use crate::utils::proxy::ProxyManager;
use tracing::warn;

#[cfg(feature = "tls-impersonation")]
// use rquest::impersonate::Impersonate;

pub struct StealthClientBuilder;

impl StealthClientBuilder {
    pub fn build(target: &TargetHost, pm: &ProxyManager) -> Result<reqwest::Client> {
        Self::create_builder(target, pm, &crate::plugins::detection_evasion::stealth_policy::StealthPolicy::default())?.build().context("Failed to build Stealth HTTP Client")
    }

    pub fn build_with_policy(target: &TargetHost, pm: &ProxyManager, policy: &crate::plugins::detection_evasion::stealth_policy::StealthPolicy) -> Result<reqwest::Client> {
        Self::create_builder(target, pm, policy)?.build().context("Failed to build Policy-driven Stealth HTTP Client")
    }

    pub fn build_pinned(target: &TargetHost, pm: &ProxyManager, host: &str, addr: std::net::SocketAddr) -> Result<reqwest::Client> {
        Self::create_builder(target, pm, &crate::plugins::detection_evasion::stealth_policy::StealthPolicy::default())?
            .resolve(host, addr)
            .build()
            .context("Failed to build Pinned Stealth HTTP Client")
    }

    pub fn build_pinned_infra(pm: &ProxyManager, host: &str, addr: std::net::SocketAddr) -> Result<reqwest::Client> {
        pm.configure_stealth_builder(reqwest::Client::builder())?
            .resolve(host, addr)
            .danger_accept_invalid_certs(true)
            .build()
            .context("Failed to build Pinned Infra Client")
    }

    fn create_builder(target: &TargetHost, pm: &ProxyManager, policy: &crate::plugins::detection_evasion::stealth_policy::StealthPolicy) -> Result<reqwest::ClientBuilder> {
        let mut headers = HeaderMap::new();
        let tc = &target.tactical_context;
        
        let ua = if policy.user_agent_rotation {
            crate::utils::common::get_random_user_agent().to_string()
        } else {
            tc.get("user_agent")
                .and_then(|v| v.as_str())
                .unwrap_or("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36")
                .to_string()
        };
        
        headers.insert(reqwest::header::USER_AGENT, HeaderValue::from_str(&ua)?);

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

        headers.entry(reqwest::header::ACCEPT).or_insert(HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"));
        headers.entry(reqwest::header::ACCEPT_LANGUAGE).or_insert(HeaderValue::from_static("en-US,en;q=0.9"));

        let mut builder = reqwest::Client::builder()
            .default_headers(headers)
            .timeout(Duration::from_secs(30))
            .danger_accept_invalid_certs(true);

        #[cfg(feature = "tls-impersonation")]
        {
            if policy.ja3_spoofing {
                // Note: We use rquest only for the final build if needed, 
                // but currently the return type is reqwest::Client.
                // Professional Fix: Impersonation requires rquest::Client.
                // For now, we keep the hook but warn if it cannot be applied to reqwest.
                warn!("⚠️ JA3 Spoofing requested but reqwest backend doesn't support impersonation directly. Use rquest backend.");
            }
        }
        
        if !policy.follow_redirects {
            builder = builder.redirect(reqwest::redirect::Policy::none());
        }

        pm.configure_stealth_builder(builder)
    }
}
