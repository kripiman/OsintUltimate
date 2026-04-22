use std::sync::Arc;
use anyhow::{Result, Context};
use crate::utils::proxy::ProxyManager;

/// Base infrastructure for all LLM providers.
/// Centralizes proxy management and secure transport creation.
pub struct BaseLlmClient {
    pub proxy_manager: Arc<ProxyManager>,
}

impl BaseLlmClient {
    pub fn new(pm: Arc<ProxyManager>) -> Self {
        Self { proxy_manager: pm }
    }

    /// Creates a secured reqwest::Client using the ProxyManager.
    /// Ensures "Fail-Closed" behavior for Sovereign OPSEC.
    pub async fn get_client(&self, api_host: &str) -> Result<reqwest::Client> {
        let (_, client) = self.proxy_manager.get_client_fail_closed(api_host)
            .context(format!("V13 OPSEC: Failed to secure transport for {} through ProxyManager.", api_host))?;
        Ok(client)
    }

    /// Common helper to extract JSON from provider responses.
    pub fn parse_extraction(&self, text: &str) -> Result<serde_json::Value> {
        use crate::utils::common::extract_json;
        let cleaned = extract_json(text);
        serde_json::from_str(cleaned).context("Failed to parse extracted JSON from AI response")
    }
}
