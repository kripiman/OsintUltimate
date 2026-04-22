use anyhow::{Result, Context};
use async_trait::async_trait;
use crate::models::{Finding, AIAnalysis, TargetHost};
use crate::core::ai::{LlmClient, ContextCompressor, AdaptiveContext, RouteLevel, CapabilityGap};
use serde_json::json;
use std::sync::Arc;

pub struct AnthropicClient {
    pub base: super::base::BaseLlmClient,
    pub key: String,
    pub model: String,
}

impl AnthropicClient {
    pub fn new(key: String, model: String, pm: Arc<crate::utils::proxy::ProxyManager>) -> Result<Self> {
        Ok(Self { 
            base: super::base::BaseLlmClient::new(pm),
            key, 
            model 
        })
    }
}

#[async_trait]
impl LlmClient for AnthropicClient {
    async fn analyze(&self, finding: &Finding, target: &TargetHost, attack_context: Option<&str>, route_level: RouteLevel, caveman: super::types::CavemanLevel) -> Result<AIAnalysis> {
        let compressed = ContextCompressor::compress_finding(finding, route_level);
        let ctx = attack_context.map(|c| format!(" Tactical Path: {}.", c)).unwrap_or_default();
        let prompt_raw = format!("Analyze this: {}. Target: {}.{} You must return a JSON object with 'summary', 'impact', 'stealth_notes', 'risk_score', 'confidence', 'mitre_attack', 'exploit_path' (DO NOT provide remediation/blue team fixes, only how to exploit), 'model'.", serde_json::to_string(&compressed)?, target.host, ctx);
        let prompt = crate::core::ai::caveman::CavemanOptimizer::optimize_prompt(&prompt_raw, caveman);
        
        let client = self.base.get_client("api.anthropic.com").await?;
        let res = client.post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", &self.key)
            .header("anthropic-version", "2023-06-01")
            .json(&json!({
                "model": self.model,
                "max_tokens": 1024,
                "messages": [{ "role": "user", "content": prompt }],
            })).send().await?.json::<serde_json::Value>().await?;
        
        let text = res["content"][0]["text"].as_str().context("Anthropic response format error")?;
        Ok(serde_json::from_value(self.base.parse_extraction(text)?)?)
    }

    async fn decide_action(&self, _finding: &Finding, _target: &TargetHost, _plugins: &[crate::plugins::PluginMetadata], _attack_context: Option<&str>, _gap: Option<&CapabilityGap>, _adaptive_context: Option<&AdaptiveContext>, _route_level: RouteLevel, _caveman: super::types::CavemanLevel) -> Result<Option<(String, serde_json::Value)>> {
        Ok(None)
    }
}
