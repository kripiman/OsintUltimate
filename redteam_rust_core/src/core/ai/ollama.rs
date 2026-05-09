use anyhow::{Result, Context};
use async_trait::async_trait;
use crate::models::AIAnalysis;
use crate::core::ai::traits::LlmClient;
use crate::core::ai::compressor::ContextCompressor;
use serde_json::json;
use std::sync::Arc;

pub struct OllamaClient {
    pub base: super::base::BaseLlmClient,
    pub url: String,
    pub model: String,
}

impl OllamaClient {
    pub fn new(url: String, model: String, pm: Arc<crate::utils::proxy::ProxyManager>) -> Result<Self> {
        Ok(Self { 
            base: super::base::BaseLlmClient::new(pm),
            url, 
            model 
        })
    }
}

#[async_trait]
impl LlmClient for OllamaClient {
    async fn analyze(&self, config: crate::core::ai::traits::InferenceConfig<'_>) -> Result<AIAnalysis> {
        let compressed = ContextCompressor::compress_finding(config.finding, config.route_level);
        let ctx_header = config.attack_context.map(|c| format!("Tactical Path: {}\n", c)).unwrap_or_default();
        let prompt_raw = format!(
            "### PROFESSIONAL RED TEAM ENGINE (v3.0) ###\n\
            Analyze this finding based on modern TTPs. Be extremely technical. Do not output defensive remediations or fixes; provide the exploit path.\n\n\
            Target: {}\n\
            {}Finding: {}\n\n\
            JSON Schema: {{ \"summary\": \"...\", \"impact\": \"...\", \"stealth_notes\": \"...\", \"risk_score\": 1-10, \"confidence\": 0.0-1.0, \"mitre_attack\": [\"T1234\"], \"exploit_path\": \"...\", \"model\": \"{}\" }}",
            serde_json::to_string(&ContextCompressor::compress_target_lean(config.target)).unwrap_or_default(), ctx_header, serde_json::to_string(&compressed)?, self.model
        );
        let prompt = crate::core::ai::caveman::CavemanOptimizer::optimize_prompt(&prompt_raw, config.caveman);

        let client = self.base.get_client("localhost").await?;
        let res: serde_json::Value = client.post(format!("{}/api/generate", self.url))
            .json(&json!({ "model": self.model, "prompt": prompt, "stream": false, "format": "json" }))
            .send().await?.json().await?;

        let response_text = res["response"].as_str().context("Ollama response missing text")?;
        let mut analysis: AIAnalysis = serde_json::from_value(self.base.parse_extraction(response_text)?)?;
        
        if let Some(prompt_tokens) = res["prompt_eval_count"].as_u64() {
            analysis.usage.prompt_tokens = prompt_tokens as u32;
        }
        if let Some(completion_tokens) = res["eval_count"].as_u64() {
            analysis.usage.completion_tokens = completion_tokens as u32;
        }
        analysis.usage.total_tokens = analysis.usage.prompt_tokens + analysis.usage.completion_tokens;
        
        Ok(analysis)
    }

    async fn decide_action(&self, config: crate::core::ai::traits::DecisionConfig<'_>) -> Result<Option<(String, serde_json::Value)>> {
        let compressed_finding = ContextCompressor::compress_finding(config.finding, config.route_level);
        let compressed_plugins = ContextCompressor::compress_plugins(config.plugins);
        let adaptive_json = serde_json::to_string(&config.adaptive_context)?;
        let ctx_header = config.attack_context.map(|c| format!("Tactical Path: {}\n", c)).unwrap_or_default();

        let prompt_raw = format!(
            "### SENTINEL ADAPTIVE ORCHESTRATOR ###\n\
            Target: {}\n\
            {}Current Finding: {}\n\
            Adaptive Context (RETRIES/BYPASSES): {}\n\
            Plugins: {}\n\n\
            Decision instructions: If previous actions failed/blocked, suggest a bypass action (different User-Agent, headers, or a different tool).\n\
            Return JSON: {{ \"action\": \"plugin_name\", \"tactical_context\": {{ \"user_agent\": \"...\", \"headers\": {{...}} }} }}",
            serde_json::to_string(&ContextCompressor::compress_target_lean(config.target)).unwrap_or_default(), ctx_header, serde_json::to_string(&compressed_finding)?, adaptive_json, serde_json::to_string(&compressed_plugins)?
        );
        let prompt = crate::core::ai::caveman::CavemanOptimizer::optimize_prompt(&prompt_raw, config.caveman);

        let client = self.base.get_client("localhost").await?;
        let res: serde_json::Value = client.post(format!("{}/api/generate", self.url))
            .json(&json!({ "model": self.model, "prompt": prompt, "stream": false, "format": "json" }))
            .send().await?.json().await?;

        let text = res["response"].as_str().context("Ollama decision missing text")?;
        let json_val: serde_json::Value = self.base.parse_extraction(text)?;
        let action = json_val["action"].as_str().unwrap_or("none");
        
        if action == "none" || !config.plugins.iter().any(|p| p.name == action) {
             Ok(None)
        } else {
             Ok(Some((action.to_string(), json_val["tactical_context"].clone())))
        }
    }
}
