use anyhow::{Result, Context};
use async_trait::async_trait;
use crate::models::{Finding, AIAnalysis, TargetHost};
use crate::core::ai::{LlmClient, ContextCompressor, AdaptiveContext, RouteLevel, CapabilityGap};
use crate::utils::common::extract_json;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;

pub struct OpenAIClient {
    pub key: String,
    pub model: String,
    pub proxy_manager: Option<Arc<crate::utils::proxy::ProxyManager>>,
}

impl OpenAIClient {
    pub fn new(key: String, model: String, pm: Option<Arc<crate::utils::proxy::ProxyManager>>) -> Result<Self> {
        Ok(Self { key, model, proxy_manager: pm })
    }
    async fn get_client(&self) -> Result<reqwest::Client> {
        if let Some(ref pm) = self.proxy_manager {
            let (_, client) = pm.get_client_fail_closed("api.openai.com")?;
            Ok(client)
        } else {
            Ok(reqwest::Client::builder().timeout(Duration::from_secs(60)).build()?)
        }
    }
}

#[async_trait]
impl LlmClient for OpenAIClient {
    async fn analyze(&self, finding: &Finding, target: &TargetHost, attack_context: Option<&str>, route_level: RouteLevel) -> Result<AIAnalysis> {
        let compressed = ContextCompressor::compress_finding(finding, route_level);
        let ctx = attack_context.map(|c| format!(" Tactical Path: {}.", c)).unwrap_or_default();
        let client = self.get_client().await?;
        let res = client.post("https://api.openai.com/v1/chat/completions")
            .header("Authorization", format!("Bearer {}", self.key))
            .json(&json!({
                "model": self.model,
                "messages": [
                    { "role": "system", "content": "### PROFESSIONAL RED TEAM ENGINE ###\nReturn strictly JSON." },
                    { "role": "user", "content": format!("Analyze this: {}. Target: {}.{}", serde_json::to_string(&compressed)?, target.host, ctx) }
                ],
                "response_format": { "type": "json_object" }
            })).send().await?.json::<serde_json::Value>().await?;
        
        let text = res["choices"][0]["message"]["content"].as_str().context("OpenAI error")?;
        Ok(serde_json::from_str(extract_json(text))?)
    }

    async fn decide_action(&self, _finding: &Finding, _target: &TargetHost, _plugins: &[crate::plugins::PluginMetadata], _attack_context: Option<&str>, _gap: Option<&CapabilityGap>, _adaptive_context: Option<&AdaptiveContext>, _route_level: RouteLevel) -> Result<Option<(String, serde_json::Value)>> {
        Ok(None)
    }
}
