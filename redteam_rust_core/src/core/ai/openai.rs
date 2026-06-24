use anyhow::{Result, Context};
use async_trait::async_trait;
use crate::models::AIAnalysis;
use crate::core::ai::traits::LlmClient;
use crate::core::ai::compressor::ContextCompressor;
use serde_json::json;
use std::sync::Arc;

pub struct OpenAIClient {
    pub base: super::base::BaseLlmClient,
    pub key: String,
    pub model: String,
}

impl OpenAIClient {
    pub fn new(key: String, model: String, base_url: Option<String>, pm: Arc<crate::utils::proxy::ProxyManager>) -> Result<Self> {
        let base = super::base::BaseLlmClient::new(pm);
        let base = if let Some(url) = base_url {
            let mut client = base;
            client.base_url = url;
            client
        } else {
            base
        };
        Ok(Self { 
            base,
            key, 
            model 
        })
    }
}

#[async_trait]
impl LlmClient for OpenAIClient {
    async fn analyze(&self, config: crate::core::ai::traits::InferenceConfig<'_>) -> Result<AIAnalysis> {
        let compressed = ContextCompressor::compress_finding(config.finding, config.route_level);
        let ctx = config.attack_context.map(|c| format!(" Tactical Path: {}.", c)).unwrap_or_default();
        let prompt_raw = format!("Analyze this: {}. Target: {}.{}", serde_json::to_string(&compressed)?, serde_json::to_string(&ContextCompressor::compress_target_lean(config.target)).unwrap_or_default(), ctx);
        let prompt = crate::core::ai::caveman::CavemanOptimizer::optimize_prompt(&prompt_raw, config.caveman);
        
        let (client, host, endpoint) = if !self.base.base_url.is_empty() {
            let host = url::Url::parse(&self.base.base_url)?.host_str().unwrap_or("api.openai.com").to_string();
            let endpoint = format!("{}/chat/completions", self.base.base_url.trim_end_matches('/'));
            (self.base.get_client(&host).await?, host, endpoint)
        } else {
            (self.base.get_client("api.openai.com").await?, "api.openai.com".to_string(), "https://api.openai.com/v1/chat/completions".to_string())
        };

        let res = client.post(&endpoint)
            .header("Authorization", format!("Bearer {}", self.key))
            .json(&json!({
                "model": self.model,
                "messages": [
                    { "role": "system", "content": "### PROFESSIONAL RED TEAM ENGINE ###\nReturn strictly JSON. You must include these fields: 'summary', 'impact', 'stealth_notes', 'risk_score', 'confidence', 'mitre_attack', 'exploit_path', 'model'. DO NOT output defensive remediations or fixes; provide the exploit path." },
                    { "role": "user", "content": prompt }
                ],
                "response_format": { "type": "json_object" }
            })).send().await?.json::<serde_json::Value>().await?;
        
        let text = res["choices"][0]["message"]["content"].as_str().context("OpenAI response format error")?;
        Ok(serde_json::from_value(self.base.parse_extraction(text)?)?)
    }

    async fn decide_action(&self, config: crate::core::ai::traits::DecisionConfig<'_>) -> Result<Option<(String, serde_json::Value)>> {
        let _ = ContextCompressor::compress_finding(config.finding, config.route_level);
        let ctx = config.attack_context.map(|c| format!("\nTactical Path: {}", c)).unwrap_or_default();
        let prompt_raw = format!("Target: {}{}, Finding: {}, Context: {:?}", config.target.host, ctx, config.finding.id, config.adaptive_context);
        let prompt = crate::core::ai::caveman::CavemanOptimizer::optimize_prompt(&prompt_raw, config.caveman);
        
        let (client, _, endpoint) = if !self.base.base_url.is_empty() {
            let host = url::Url::parse(&self.base.base_url)?.host_str().unwrap_or("api.openai.com").to_string();
            let endpoint = format!("{}/chat/completions", self.base.base_url.trim_end_matches('/'));
            (self.base.get_client(&host).await?, host, endpoint)
        } else {
            (self.base.get_client("api.openai.com").await?, "api.openai.com".to_string(), "https://api.openai.com/v1/chat/completions".to_string())
        };

        let res = client.post(&endpoint)
            .header("Authorization", format!("Bearer {}", self.key))
            .json(&json!({
                "model": self.model,
                "messages": [
                    { "role": "system", "content": "### SENTINEL ORCHESTRATOR ###\nReturn JSON: {\"action\": \"name\", \"tactical_context\": {}}" },
                    { "role": "user", "content": prompt }
                ],
                "response_format": { "type": "json_object" }
            })).send().await?.json::<serde_json::Value>().await?;

        let text = res["choices"][0]["message"]["content"].as_str().context("OpenAI decision format error")?;
        let json_val: serde_json::Value = self.base.parse_extraction(text)?;
        let action = json_val["action"].as_str().unwrap_or("none");
        if action == "none" || !config.plugins.iter().any(|p| p.name == action) { Ok(None) }
        else { Ok(Some((action.to_string(), json_val["tactical_context"].clone()))) }
    }
}
