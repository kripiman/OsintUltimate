use anyhow::Result;
use async_trait::async_trait;
use crate::models::AIAnalysis;
use crate::core::ai::LlmClient;
use crate::core::ai::ContextCompressor;
use serde_json::json;
use std::sync::Arc;

pub struct GeminiClient {
    pub base: super::base::BaseLlmClient,
    pub keys: Vec<String>,
    pub current_key_idx: std::sync::atomic::AtomicUsize,
    pub model: String,
}

impl GeminiClient {
    pub fn new(keys: Vec<String>, model: String, pm: Arc<crate::utils::proxy::ProxyManager>) -> Result<Self> {
        if keys.is_empty() { anyhow::bail!("GeminiClient requires keys"); }
        Ok(Self { 
            base: super::base::BaseLlmClient::new(pm),
            keys, 
            current_key_idx: std::sync::atomic::AtomicUsize::new(0), 
            model 
        })
    }
    fn get_key(&self) -> &str {
        let idx = self.current_key_idx.load(std::sync::atomic::Ordering::Relaxed);
        &self.keys[idx % self.keys.len()]
    }
    fn rotate_key(&self) {
        self.current_key_idx.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

#[async_trait]
impl LlmClient for GeminiClient {
    async fn analyze(&self, config: crate::core::ai::traits::InferenceConfig<'_>) -> Result<AIAnalysis> {
        let compressed = ContextCompressor::compress_finding(config.finding, config.route_level);
        let ctx_header = config.attack_context.map(|c| format!("Tactical Path: {}\n", c)).unwrap_or_default();
        let prompt_raw = format!("### PROFESSIONAL RED TEAM ENGINE ###\n{}Analyze this Red Team finding: {}. Target: {}. You must return a JSON object with 'summary', 'impact', 'stealth_notes', 'risk_score', 'confidence', 'mitre_attack', 'exploit_path' (DO NOT provide remediation/blue team fixes, only how to exploit), 'model'.", ctx_header, serde_json::to_string(&compressed)?, serde_json::to_string(&ContextCompressor::compress_target_lean(config.target)).unwrap_or_default());
        let prompt = crate::core::ai::caveman::CavemanOptimizer::optimize_prompt(&prompt_raw, config.caveman);
        
        let mut last_error = None;
        let client = self.base.get_client("generativelanguage.googleapis.com").await?;
        for _ in 0..self.keys.len() {
            let url = format!("https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent?key={}", self.model, self.get_key());
            match client.post(url).json(&json!({ "contents": [{ "parts": [{ "text": prompt }] }], "generationConfig": { "response_mime_type": "application/json" } })).send().await {
                Ok(res) => {
                    let val = res.json::<serde_json::Value>().await?;
                    if let Some(text) = val["candidates"][0]["content"]["parts"][0]["text"].as_str() {
                        let mut analysis: AIAnalysis = serde_json::from_value(self.base.parse_extraction(text)?)?;
                        
                        // Gemini token usage
                        if let Some(usage) = val["usageMetadata"].as_object() {
                            analysis.usage.prompt_tokens = usage.get("promptTokenCount").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                            analysis.usage.completion_tokens = usage.get("candidatesTokenCount").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                            analysis.usage.total_tokens = usage.get("totalTokenCount").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                        }
                        
                        return Ok(analysis);
                    }
                    self.rotate_key();
                }
                Err(e) => { self.rotate_key(); last_error = Some(e); }
            }
        }
        Err(anyhow::anyhow!("Gemini analyze failed: {:?}", last_error))
    }

    async fn decide_action(&self, config: crate::core::ai::traits::DecisionConfig<'_>) -> Result<Option<(String, serde_json::Value)>> {
        let _ = ContextCompressor::compress_finding(config.finding, config.route_level);
        let ctx_header = config.attack_context.map(|c| format!("Tactical Path: {}\n", c)).unwrap_or_default();
        let prompt_raw = format!("### SENTINEL ORCHESTRATOR ###\n{}Decide next step for {}. History: {:?}. Finding: {}. Plugins: {}. Focus on WAF bypass.", ctx_header, serde_json::to_string(&ContextCompressor::compress_target_lean(config.target)).unwrap_or_default(), config.adaptive_context, config.finding.id, config.plugins.len());
        let prompt = crate::core::ai::caveman::CavemanOptimizer::optimize_prompt(&prompt_raw, config.caveman);
        
        let client = self.base.get_client("generativelanguage.googleapis.com").await?;
        for _ in 0..self.keys.len() {
            let url = format!("https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent?key={}", self.model, self.get_key());
            match client.post(url).json(&json!({ "contents": [{ "parts": [{ "text": prompt }] }], "generationConfig": { "response_mime_type": "application/json" } })).send().await {
                Ok(res) => {
                    let val = res.json::<serde_json::Value>().await?;
                    if let Some(text) = val["candidates"][0]["content"]["parts"][0]["text"].as_str() {
                        let json_val: serde_json::Value = self.base.parse_extraction(text)?;
                        let action = json_val["action"].as_str().unwrap_or("none");
                        if action == "none" || !config.plugins.iter().any(|p| p.name == action) { return Ok(None); }
                        return Ok(Some((action.to_string(), json_val["tactical_context"].clone())));
                    }
                    self.rotate_key();
                }
                Err(_) => self.rotate_key(),
            }
        }
        Ok(None)
    }
}
