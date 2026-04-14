use anyhow::{Result, Context};
use async_trait::async_trait;
use crate::models::{Finding, AIAnalysis, TargetHost};
use crate::core::ai::{LlmClient, ContextCompressor, AdaptiveContext, RouteLevel, CapabilityGap};
use crate::utils::common::extract_json;
use serde_json::json;
use std::sync::Arc;

pub struct GeminiClient {
    pub keys: Vec<String>,
    pub current_key_idx: std::sync::atomic::AtomicUsize,
    pub model: String,
    pub proxy_manager: Option<Arc<crate::utils::proxy::ProxyManager>>,
}

impl GeminiClient {
    pub fn new(keys: Vec<String>, model: String, pm: Option<Arc<crate::utils::proxy::ProxyManager>>) -> Result<Self> {
        if keys.is_empty() { anyhow::bail!("GeminiClient requires keys"); }
        Ok(Self { keys, current_key_idx: std::sync::atomic::AtomicUsize::new(0), model, proxy_manager: pm })
    }
    async fn get_client(&self) -> Result<reqwest::Client> {
        let pm = self.proxy_manager.as_ref()
            .context("V13 OPSEC Violation: GeminiClient requires an active ProxyManager for Sovereign Stealth.")?;
        
        let (_, client) = pm.get_client_fail_closed("generativelanguage.googleapis.com")?;
        Ok(client)
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
    async fn analyze(&self, finding: &Finding, target: &TargetHost, attack_context: Option<&str>, route_level: RouteLevel) -> Result<AIAnalysis> {
        let compressed = ContextCompressor::compress_finding(finding, route_level);
        let ctx_header = attack_context.map(|c| format!("Tactical Path: {}\n", c)).unwrap_or_default();
        let prompt = format!("### PROFESSIONAL RED TEAM ENGINE ###\n{}Analyze this Red Team finding: {}. Target: {}. Provide JSON.", ctx_header, serde_json::to_string(&compressed)?, target.host);
        
        let mut last_error = None;
        let client = self.get_client().await?;
        for _ in 0..self.keys.len() {
            let url = format!("https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent?key={}", self.model, self.get_key());
            match client.post(url).json(&json!({ "contents": [{ "parts": [{ "text": prompt }] }], "generationConfig": { "response_mime_type": "application/json" } })).send().await {
                Ok(res) => {
                    let val = res.json::<serde_json::Value>().await?;
                    if let Some(text) = val["candidates"][0]["content"]["parts"][0]["text"].as_str() {
                        let mut analysis: AIAnalysis = serde_json::from_str(extract_json(text))?;
                        
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

    async fn decide_action(&self, finding: &Finding, target: &TargetHost, plugins: &[crate::plugins::PluginMetadata], attack_context: Option<&str>, _gap: Option<&CapabilityGap>, adaptive_context: Option<&AdaptiveContext>, route_level: RouteLevel) -> Result<Option<(String, serde_json::Value)>> {
        let _ = ContextCompressor::compress_finding(finding, route_level);
        let ctx_header = attack_context.map(|c| format!("Tactical Path: {}\n", c)).unwrap_or_default();
        let prompt = format!("### SENTINEL ORCHESTRATOR ###\n{}Decide next step for {}. History: {:?}. Finding: {}. Plugins: {}. Focus on WAF bypass.", ctx_header, target.host, adaptive_context, finding.id, plugins.len());
        
        let client = self.get_client().await?;
        for _ in 0..self.keys.len() {
            let url = format!("https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent?key={}", self.model, self.get_key());
            match client.post(url).json(&json!({ "contents": [{ "parts": [{ "text": prompt }] }], "generationConfig": { "response_mime_type": "application/json" } })).send().await {
                Ok(res) => {
                    let val = res.json::<serde_json::Value>().await?;
                    if let Some(text) = val["candidates"][0]["content"]["parts"][0]["text"].as_str() {
                        let json_val: serde_json::Value = serde_json::from_str(extract_json(text))?;
                        let action = json_val["action"].as_str().unwrap_or("none");
                        if action == "none" || !plugins.iter().any(|p| p.name == action) { return Ok(None); }
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
