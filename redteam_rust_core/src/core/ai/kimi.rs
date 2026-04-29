use anyhow::{Result, Context};
use async_trait::async_trait;
use crate::models::AIAnalysis;
use crate::core::ai::traits::LlmClient;
use crate::core::ai::compressor::ContextCompressor;
use serde_json::json;
use std::sync::Arc;

pub struct KimiClient {
    pub base: super::base::BaseLlmClient,
    pub key: String,
    pub model: String,
}

impl KimiClient {
    pub fn new(key: String, model: String, pm: Arc<crate::utils::proxy::ProxyManager>) -> Result<Self> {
        Ok(Self { 
            base: super::base::BaseLlmClient::new(pm),
            key, 
            model 
        })
    }
}

#[async_trait]
impl LlmClient for KimiClient {
    async fn analyze(&self, config: crate::core::ai::traits::InferenceConfig<'_>) -> Result<AIAnalysis> {
        let compressed = ContextCompressor::compress_finding(config.finding, config.route_level);
        let ctx = config.attack_context.map(|c| format!(" Tactical Path: {}.", c)).unwrap_or_default();
        let prompt_raw = format!("Analyze this: {}. Target: {}.{}", serde_json::to_string(&compressed)?, config.target.host, ctx);
        let prompt = crate::core::ai::caveman::CavemanOptimizer::optimize_prompt(&prompt_raw, config.caveman);
        
        let client = self.base.get_client("api.kimi.com").await?;
        let res = client.post("https://api.kimi.com/coding/v1/chat/completions")
            .header("Authorization", format!("Bearer {}", self.key))
            .json(&json!({
                "model": self.model,
                "messages": [
                    { "role": "system", "content": "### PROFESSIONAL RED TEAM ENGINE ###\nReturn strictly JSON. You must include these fields: 'summary', 'impact', 'stealth_notes', 'risk_score', 'confidence', 'mitre_attack', 'exploit_path', 'model'. DO NOT output defensive remediations or fixes; provide the exploit path." },
                    { "role": "user", "content": prompt }
                ],
                "response_format": { "type": "json_object" }
            })).send().await?.json::<serde_json::Value>().await?;
        
        let text = res["choices"][0]["message"]["content"].as_str().context("Kimi Code API response format error")?;
        Ok(serde_json::from_value(self.base.parse_extraction(text)?)?)
    }

    async fn decide_action(&self, config: crate::core::ai::traits::DecisionConfig<'_>) -> Result<Option<(String, serde_json::Value)>> {
        let _ = crate::core::ai::compressor::ContextCompressor::compress_finding(config.finding, config.route_level);
        let ctx_header = config.attack_context.map(|c| format!("Tactical Path: {}\n", c)).unwrap_or_default();
        let prompt_raw = format!("### SENTINEL ORCHESTRATOR ###\n{}Decide next step for {}. History: {:?}. Finding: {}. Plugins: {}. Focus on WAF bypass. Return JSON with 'action' (must match a plugin name exactly or 'none') and 'tactical_context' (JSON object).", ctx_header, config.target.host, config.adaptive_context, config.finding.id, config.plugins.len());
        let prompt = crate::core::ai::caveman::CavemanOptimizer::optimize_prompt(&prompt_raw, config.caveman);
        
        let client = self.base.get_client("api.kimi.com").await?;
        let res = client.post("https://api.kimi.com/coding/v1/chat/completions")
            .header("Authorization", format!("Bearer {}", self.key))
            .json(&serde_json::json!({
                "model": self.model,
                "messages": [
                    { "role": "system", "content": "You are a Sentinel Orchestrator. Return strictly JSON with 'action' and 'tactical_context'." },
                    { "role": "user", "content": prompt }
                ],
                "response_format": { "type": "json_object" }
            })).send().await?.json::<serde_json::Value>().await?;
        
        if let Some(text) = res["choices"][0]["message"]["content"].as_str() {
            if let Ok(json_val) = self.base.parse_extraction(text) {
                let action = json_val["action"].as_str().unwrap_or("none");
                if action == "none" || !config.plugins.iter().any(|p| p.name == action) { return Ok(None); }
                return Ok(Some((action.to_string(), json_val["tactical_context"].clone())));
            }
        }
        Ok(None)
    }
}
