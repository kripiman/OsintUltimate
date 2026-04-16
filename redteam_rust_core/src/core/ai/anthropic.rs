use anyhow::{Result, Context};
use async_trait::async_trait;
use crate::models::{Finding, AIAnalysis, TargetHost};
use crate::core::ai::{LlmClient, ContextCompressor, AdaptiveContext, RouteLevel, CapabilityGap};
use crate::utils::common::extract_json;
use serde_json::json;
use std::sync::Arc;

pub struct AnthropicClient {
    pub key: String,
    pub model: String,
    pub proxy_manager: Option<Arc<crate::utils::proxy::ProxyManager>>,
}

impl AnthropicClient {
    pub fn new(key: String, model: String, pm: Option<Arc<crate::utils::proxy::ProxyManager>>) -> Result<Self> {
        Ok(Self { key, model, proxy_manager: pm })
    }
    async fn get_client(&self) -> Result<reqwest::Client> {
        let pm = self.proxy_manager.as_ref()
            .context("V13 OPSEC Violation: AnthropicClient requires an active ProxyManager for Sovereign Stealth.")?;
        let (_, client) = pm.get_client_fail_closed("api.anthropic.com")?;
        Ok(client)
    }
}

#[async_trait]
impl LlmClient for AnthropicClient {
    async fn analyze(&self, finding: &Finding, target: &TargetHost, attack_context: Option<&str>, route_level: RouteLevel, caveman: super::types::CavemanLevel) -> Result<AIAnalysis> {
        let compressed = ContextCompressor::compress_finding(finding, route_level);
        let ctx = attack_context.map(|c| format!(" Tactical Path: {}.", c)).unwrap_or_default();
        let prompt_raw = format!("Analyze this: {}. Target: {}.{}", serde_json::to_string(&compressed)?, target.host, ctx);
        let prompt = crate::core::ai::caveman::CavemanOptimizer::optimize_prompt(&prompt_raw, caveman);
        let client = self.get_client().await?;
        let res = client.post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", &self.key)
            .header("anthropic-version", "2023-06-01")
            .json(&json!({
                "model": self.model,
                "max_tokens": 1024,
                "messages": [{ "role": "user", "content": prompt }],
            })).send().await?.json::<serde_json::Value>().await?;
        
        let text = res["content"][0]["text"].as_str().context("Anthropic error")?;
        Ok(serde_json::from_str(extract_json(text))?)
    }

    async fn decide_action(&self, _finding: &Finding, _target: &TargetHost, _plugins: &[crate::plugins::PluginMetadata], _attack_context: Option<&str>, _gap: Option<&CapabilityGap>, _adaptive_context: Option<&AdaptiveContext>, _route_level: RouteLevel, _caveman: super::types::CavemanLevel) -> Result<Option<(String, serde_json::Value)>> {
        Ok(None)
    }
}
