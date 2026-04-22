use anyhow::{Result, Context};
use async_trait::async_trait;
use crate::models::AIAnalysis;
use crate::core::ai::traits::LlmClient;
use crate::core::ai::compressor::ContextCompressor;
use serde_json::json;
use std::sync::Arc;

pub struct AzureOpenAIClient {
    pub base: super::base::BaseLlmClient,
    pub endpoint: String,
    pub key: String,
    pub deployment: String,
    pub api_version: String,
}

impl AzureOpenAIClient {
    pub fn new(endpoint: String, key: String, deployment: String, api_version: String, pm: Arc<crate::utils::proxy::ProxyManager>) -> Result<Self> {
        Ok(Self { 
            base: super::base::BaseLlmClient::new(pm),
            endpoint, 
            key, 
            deployment, 
            api_version 
        })
    }
}

#[async_trait]
impl LlmClient for AzureOpenAIClient {
    async fn analyze(&self, config: crate::core::ai::traits::InferenceConfig<'_>) -> Result<AIAnalysis> {
        let compressed = ContextCompressor::compress_finding(config.finding, config.route_level);
        let ctx = config.attack_context.map(|c| format!("\nTactical Path: {}", c)).unwrap_or_default();
        let prompt_raw = format!("Target: {}{}, Finding: {}", config.target.host, ctx, serde_json::to_string(&compressed)?);
        let prompt = crate::core::ai::caveman::CavemanOptimizer::optimize_prompt(&prompt_raw, config.caveman);
        
        let host = url::Url::parse(&self.endpoint)?.host_str().unwrap_or("openai.azure.com").to_string();
        let client = self.base.get_client(&host).await?;
        let url = format!("{}/openai/deployments/{}/chat/completions?api-version={}", self.endpoint, self.deployment, self.api_version);
        let res = client.post(url).header("api-key", &self.key).json(&json!({
            "messages": [
                { "role": "system", "content": "### PROFESSIONAL RED TEAM ENGINE ###\nReturn strictly JSON analysis. You must include these fields: 'summary', 'impact', 'stealth_notes', 'risk_score', 'confidence', 'mitre_attack', 'exploit_path', 'model'. DO NOT output defensive remediations or fixes; provide the exploit path." }, 
                { "role": "user", "content": prompt }
            ],
            "response_format": { "type": "json_object" }
        })).send().await?.json::<serde_json::Value>().await?;
        let text = res["choices"][0]["message"]["content"].as_str().context("Azure response format error")?;
        Ok(serde_json::from_value(self.base.parse_extraction(text)?)?)
    }

    async fn decide_action(&self, config: crate::core::ai::traits::DecisionConfig<'_>) -> Result<Option<(String, serde_json::Value)>> {
        let _ = ContextCompressor::compress_finding(config.finding, config.route_level);
        let ctx = config.attack_context.map(|c| format!("\nTactical Path: {}", c)).unwrap_or_default();
        let prompt_raw = format!("Target: {}{}, Finding: {}, Context: {:?}", config.target.host, ctx, config.finding.id, config.adaptive_context);
        let prompt = crate::core::ai::caveman::CavemanOptimizer::optimize_prompt(&prompt_raw, config.caveman);
        
        let host = url::Url::parse(&self.endpoint)?.host_str().unwrap_or("openai.azure.com").to_string();
        let client = self.base.get_client(&host).await?;
        let url = format!("{}/openai/deployments/{}/chat/completions?api-version={}", self.endpoint, self.deployment, self.api_version);
        let res = client.post(url).header("api-key", &self.key).json(&json!({
            "messages": [
                { "role": "system", "content": "### SENTINEL ORCHESTRATOR ###\nReturn JSON: {\"action\": \"name\", \"tactical_context\": {}}" },
                { "role": "user", "content": prompt }
            ],
            "response_format": { "type": "json_object" }
        })).send().await?.json::<serde_json::Value>().await?;
        let text = res["choices"][0]["message"]["content"].as_str().context("Azure decision format error")?;
        let json_val: serde_json::Value = self.base.parse_extraction(text)?;
        let action = json_val["action"].as_str().unwrap_or("none");
        if action == "none" || !config.plugins.iter().any(|p| p.name == action) { Ok(None) }
        else { Ok(Some((action.to_string(), json_val["tactical_context"].clone()))) }
    }
}
