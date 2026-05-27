use anyhow::{Result, Context};
use async_trait::async_trait;
use crate::models::AIAnalysis;
use crate::core::ai::traits::LlmClient;
use crate::core::ai::compressor::ContextCompressor;
use serde_json::json;
use std::sync::Arc;

pub struct GoogleAIStudioClient {
    pub base: super::base::BaseLlmClient,
    pub key: String,
    pub model: String,
}

impl GoogleAIStudioClient {
    pub fn new(key: String, model: String, pm: Arc<crate::utils::proxy::ProxyManager>) -> Result<Self> {
        Ok(Self {
            base: super::base::BaseLlmClient::new(pm),
            key,
            model,
        })
    }
}

#[async_trait]
impl LlmClient for GoogleAIStudioClient {
    async fn analyze(&self, config: crate::core::ai::traits::InferenceConfig<'_>) -> Result<AIAnalysis> {
        let compressed = ContextCompressor::compress_finding(config.finding, config.route_level);
        let ctx_header = config.attack_context.map(|c| format!("Tactical Path: {}\n", c)).unwrap_or_default();
        let prompt_raw = format!("{}Analyze this Red Team finding: {}. Target: {}. You must return a JSON object with 'summary', 'impact', 'stealth_notes', 'risk_score', 'confidence', 'mitre_attack', 'exploit_path' (DO NOT provide remediation/blue team fixes, only how to exploit), 'model'.", ctx_header, serde_json::to_string(&compressed)?, config.target.host);
        let prompt = crate::core::ai::caveman::CavemanOptimizer::optimize_prompt(&prompt_raw, config.caveman);

        let client = self.base.get_client("generativelanguage.googleapis.com").await?;
        let url = format!("https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent?key={}", self.model, self.key);
        let res = client.post(&url)
            .json(&json!({
                "contents": [{ "parts": [{ "text": prompt }] }],
                "generationConfig": { "response_mime_type": "application/json" }
            })).send().await?.json::<serde_json::Value>().await?;

        let text = res["candidates"][0]["content"]["parts"][0]["text"].as_str().context("Google AI Studio response format error")?;
        let mut analysis: AIAnalysis = serde_json::from_value(self.base.parse_extraction(text)?)?;

        if let Some(usage) = res["usageMetadata"].as_object() {
            analysis.usage.prompt_tokens = usage.get("promptTokenCount").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            analysis.usage.completion_tokens = usage.get("candidatesTokenCount").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            analysis.usage.total_tokens = usage.get("totalTokenCount").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
        }

        Ok(analysis)
    }

    async fn decide_action(&self, config: crate::core::ai::traits::DecisionConfig<'_>) -> Result<Option<(String, serde_json::Value)>> {
        let ctx_header = config.attack_context.map(|c| format!("Tactical Path: {}\n", c)).unwrap_or_default();
        let prompt_raw = format!("{}Decide next step for {}. History: {:?}. Finding: {}. Plugins: {}. Focus on WAF bypass. Return JSON with 'action' (must match a plugin name exactly or 'none') and 'tactical_context' (JSON object).", ctx_header, config.target.host, config.adaptive_context, config.finding.id, config.plugins.len());
        let prompt = crate::core::ai::caveman::CavemanOptimizer::optimize_prompt(&prompt_raw, config.caveman);

        let client = self.base.get_client("generativelanguage.googleapis.com").await?;
        let url = format!("https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent?key={}", self.model, self.key);
        let res = client.post(&url)
            .json(&json!({
                "contents": [{ "parts": [{ "text": prompt }] }],
                "generationConfig": { "response_mime_type": "application/json" }
            })).send().await?.json::<serde_json::Value>().await?;

        if let Some(text) = res["candidates"][0]["content"]["parts"][0]["text"].as_str() {
            if let Ok(json_val) = self.base.parse_extraction(text) {
                let action = json_val["action"].as_str().unwrap_or("none");
                if action == "none" || !config.plugins.iter().any(|p| p.name == action) { return Ok(None); }
                return Ok(Some((action.to_string(), json_val["tactical_context"].clone())));
            }
        }
        Ok(None)
    }
}
