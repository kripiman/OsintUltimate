use anyhow::{Result, Context};
use async_trait::async_trait;
use crate::models::{Finding, AIAnalysis, TargetHost};
use crate::core::ai::{LlmClient, ContextCompressor, AdaptiveContext, RouteLevel, CapabilityGap};
use crate::utils::common::extract_json;
use serde_json::json;
use std::sync::Arc;

pub struct AzureOpenAIClient {
    pub endpoint: String,
    pub key: String,
    pub deployment: String,
    pub api_version: String,
    pub proxy_manager: Option<Arc<crate::utils::proxy::ProxyManager>>,
}

impl AzureOpenAIClient {
    pub fn new(endpoint: String, key: String, deployment: String, api_version: String, pm: Option<Arc<crate::utils::proxy::ProxyManager>>) -> Result<Self> {
        Ok(Self { endpoint, key, deployment, api_version, proxy_manager: pm })
    }
    async fn get_client(&self) -> Result<reqwest::Client> {
        let pm = self.proxy_manager.as_ref()
            .context("V13 OPSEC Violation: AzureOpenAIClient requires an active ProxyManager for Sovereign Stealth.")?;
        
        let host = url::Url::parse(&self.endpoint)?.host_str().unwrap_or("openai.azure.com").to_string();
        let (_, client) = pm.get_client_fail_closed(&host)?;
        Ok(client)
    }
}

#[async_trait]
impl LlmClient for AzureOpenAIClient {
    async fn analyze(&self, finding: &Finding, target: &TargetHost, attack_context: Option<&str>, route_level: RouteLevel) -> Result<AIAnalysis> {
        let compressed = ContextCompressor::compress_finding(finding, route_level);
        let ctx = attack_context.map(|c| format!("\nTactical Path: {}", c)).unwrap_or_default();
        let client = self.get_client().await?;
        let url = format!("{}/openai/deployments/{}/chat/completions?api-version={}", self.endpoint, self.deployment, self.api_version);
        let res = client.post(url).header("api-key", &self.key).json(&json!({
            "messages": [
                { "role": "system", "content": "### PROFESSIONAL RED TEAM ENGINE ###\nReturn strictly JSON analysis." }, 
                { "role": "user", "content": format!("Target: {}{}, Finding: {}", target.host, ctx, serde_json::to_string(&compressed)?) }
            ],
            "response_format": { "type": "json_object" }
        })).send().await?.json::<serde_json::Value>().await?;
        let text = res["choices"][0]["message"]["content"].as_str().context("Azure error")?;
        Ok(serde_json::from_str(extract_json(text))?)
    }

    async fn decide_action(&self, finding: &Finding, target: &TargetHost, plugins: &[crate::plugins::PluginMetadata], attack_context: Option<&str>, _gap: Option<&CapabilityGap>, adaptive_context: Option<&AdaptiveContext>, route_level: RouteLevel) -> Result<Option<(String, serde_json::Value)>> {
        let _ = ContextCompressor::compress_finding(finding, route_level);
        let ctx = attack_context.map(|c| format!("\nTactical Path: {}", c)).unwrap_or_default();
        let client = self.get_client().await?;
        let url = format!("{}/openai/deployments/{}/chat/completions?api-version={}", self.endpoint, self.deployment, self.api_version);
        let res = client.post(url).header("api-key", &self.key).json(&json!({
            "messages": [
                { "role": "system", "content": "### SENTINEL ORCHESTRATOR ###\nReturn JSON: {\"action\": \"name\", \"tactical_context\": {}}" },
                { "role": "user", "content": format!("Target: {}{}, Finding: {}, Context: {:?}", target.host, ctx, finding.id, adaptive_context) }
            ],
            "response_format": { "type": "json_object" }
        })).send().await?.json::<serde_json::Value>().await?;
        let text = res["choices"][0]["message"]["content"].as_str().context("Azure decision error")?;
        let json_val: serde_json::Value = serde_json::from_str(extract_json(text))?;
        let action = json_val["action"].as_str().unwrap_or("none");
        if action == "none" || !plugins.iter().any(|p| p.name == action) { Ok(None) }
        else { Ok(Some((action.to_string(), json_val["tactical_context"].clone()))) }
    }
}
