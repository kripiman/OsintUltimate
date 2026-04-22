use anyhow::{Result, Context};
use async_trait::async_trait;
use crate::models::AIAnalysis;
use crate::core::ai::traits::LlmClient;
use crate::core::ai::compressor::ContextCompressor;
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
    async fn analyze(&self, config: crate::core::ai::traits::InferenceConfig<'_>) -> Result<AIAnalysis> {
        let compressed = ContextCompressor::compress_finding(config.finding, config.route_level);
        let ctx = config.attack_context.map(|c| format!(" Tactical Path: {}.", c)).unwrap_or_default();
        let prompt_raw = format!("Analyze this: {}. Target: {}.{} You must return a JSON object with 'summary', 'impact', 'stealth_notes', 'risk_score', 'confidence', 'mitre_attack', 'exploit_path' (DO NOT provide remediation/blue team fixes, only how to exploit), 'model'.", serde_json::to_string(&compressed)?, config.target.host, ctx);
        let prompt = crate::core::ai::caveman::CavemanOptimizer::optimize_prompt(&prompt_raw, config.caveman);
        
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

    async fn decide_action(&self, _config: crate::core::ai::traits::DecisionConfig<'_>) -> Result<Option<(String, serde_json::Value)>> {
        Ok(None)
    }
}
