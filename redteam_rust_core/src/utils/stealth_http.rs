use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use crate::models::TargetHost;
use anyhow::{Result, Context};
use std::time::Duration;
use crate::utils::proxy::ProxyManager;

#[cfg(feature = "tls-impersonation")]
use wreq_util::Emulation;

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
            // Note: For high-fidelity TLS impersonation, use build_impersonated() which returns a wreq::Client.
            // reqwest::ClientBuilder does not support JA3/JA4 spoofing natively.
        }
        
        if !policy.follow_redirects {
            builder = builder.redirect(reqwest::redirect::Policy::none());
        }

        pm.configure_stealth_builder(builder)
    }

    /// Build a wreq::Client configured for TLS fingerprint impersonation.
    /// Proxy routing is inherited from the ProxyManager (SOCKS5 path).
    /// Only available with the `tls-impersonation` feature.
    #[cfg(feature = "tls-impersonation")]
    pub fn build_impersonated(
        pm: &ProxyManager,
        emulation: Emulation,
    ) -> Result<wreq::Client> {
        let mut builder = wreq::Client::builder().emulation(emulation);
        if let Some(proxy_url) = pm.pick_best_proxy() {
            let proxy = wreq::Proxy::all(&proxy_url)
                .context("Invalid proxy URL for wreq impersonation client")?;
            builder = builder.proxy(proxy);
        }
        builder
            .timeout(Duration::from_secs(30))
            .build()
            .context("Failed to build wreq impersonation client")
    }

    /// Convenience builder: Chrome126 TLS fingerprint profile.
    #[cfg(feature = "tls-impersonation")]
    pub fn build_impersonated_chrome(pm: &ProxyManager) -> Result<wreq::Client> {
        // Emulation::Chrome126 verified against wreq-util v2.2.6 at compile time.
        Self::build_impersonated(pm, Emulation::Chrome126)
    }
}
