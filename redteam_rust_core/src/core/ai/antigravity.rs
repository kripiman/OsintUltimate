use anyhow::{Result, Context};
use async_trait::async_trait;
use crate::models::{Finding, AIAnalysis, TargetHost};
use crate::core::ai::{LlmClient, ContextCompressor, AdaptiveContext, RouteLevel, CapabilityGap};
use serde_json::json;
use std::sync::Arc;

/// V15: Antigravity Client for Failover Bridge (MCP-OSINTULT port)
/// Uses a custom/open-source endpoint for LLM requests when primary tiers fail (401).
pub struct AntigravityClient {
    pub base: super::base::BaseLlmClient,
    pub key: String,
    pub model: String,
    pub endpoint: String,
}

impl AntigravityClient {
    pub fn new(key: String, model: String, endpoint: String, pm: Arc<crate::utils::proxy::ProxyManager>) -> Result<Self> {
        Ok(Self { 
            base: super::base::BaseLlmClient::new(pm),
            key, 
            model, 
            endpoint 
        })
    }
}

#[async_trait]
impl LlmClient for AntigravityClient {
    async fn analyze(&self, finding: &Finding, target: &TargetHost, attack_context: Option<&str>, route_level: RouteLevel, caveman: super::types::CavemanLevel) -> Result<AIAnalysis> {
        let compressed = ContextCompressor::compress_finding(finding, route_level);
        let ctx = attack_context.map(|c| format!(" Tactical Path: {}.", c)).unwrap_or_default();
        let prompt_raw = format!("Analyze this: {}. Target: {}.{}", serde_json::to_string(&compressed)?, target.host, ctx);
        let prompt = crate::core::ai::caveman::CavemanOptimizer::optimize_prompt(&prompt_raw, caveman);
        
        let url_obj = url::Url::parse(&self.endpoint)?;
        let host = url_obj.host_str().unwrap_or("antigravity-server");
        let client = self.base.get_client(host).await?;
        let res = client.post(&format!("{}/v1/chat/completions", self.endpoint))
            .header("Authorization", format!("Bearer {}", self.key))
            .json(&json!({
                "model": self.model,
                "messages": [
                    { "role": "system", "content": "### SOVEREIGN FAILOVER ENGINE ###\nReturn strictly JSON. You must include these fields: 'summary', 'impact', 'stealth_notes', 'risk_score', 'confidence', 'mitre_attack', 'exploit_path', 'model'. DO NOT output defensive remediations or fixes; provide the exploit path." },
                    { "role": "user", "content": prompt }
                ],
                "response_format": { "type": "json_object" }
            })).send().await?.json::<serde_json::Value>().await?;
        
        let text = res["choices"][0]["message"]["content"].as_str().context("Antigravity response format error")?;
        let mut analysis: AIAnalysis = serde_json::from_value(self.base.parse_extraction(text)?)?;
        analysis.model = format!("{} (Antigravity Failover)", analysis.model);
        Ok(analysis)
    }

    async fn decide_action(&self, _finding: &Finding, _target: &TargetHost, _plugins: &[crate::plugins::PluginMetadata], _attack_context: Option<&str>, _gap: Option<&CapabilityGap>, _adaptive_context: Option<&AdaptiveContext>, _route_level: RouteLevel, _caveman: super::types::CavemanLevel) -> Result<Option<(String, serde_json::Value)>> {
        Ok(None)
    }
}
