use anyhow::{Result, Context};
use async_trait::async_trait;
use crate::models::{Finding, AIAnalysis, TargetHost};
use crate::core::ai::{LlmClient, ContextCompressor, AdaptiveContext, RouteLevel, CapabilityGap};
use crate::utils::common::extract_json;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;

pub struct OllamaClient {
    pub url: String,
    pub model: String,
    pub proxy_manager: Option<Arc<crate::utils::proxy::ProxyManager>>,
}

impl OllamaClient {
    pub fn new(url: String, model: String, pm: Option<Arc<crate::utils::proxy::ProxyManager>>) -> Result<Self> {
        Ok(Self { url, model, proxy_manager: pm })
    }

    async fn get_client(&self) -> Result<reqwest::Client> {
        if let Some(ref pm) = self.proxy_manager {
            let host = url::Url::parse(&self.url)?.host_str().unwrap_or("localhost").to_string();
            let (_, client) = pm.get_client_fail_closed(&host)?;
            Ok(client)
        } else {
            reqwest::Client::builder()
                .timeout(Duration::from_secs(60))
                .build()
                .context("Failed to build Ollama client")
        }
    }
}

#[async_trait]
impl LlmClient for OllamaClient {
    async fn analyze(&self, finding: &Finding, target: &TargetHost, attack_context: Option<&str>, route_level: RouteLevel) -> Result<AIAnalysis> {
        let compressed = ContextCompressor::compress_finding(finding, route_level);
        let ctx_header = attack_context.map(|c| format!("Tactical Path: {}\n", c)).unwrap_or_default();
        let prompt = format!(
            "### PROFESSIONAL RED TEAM ENGINE (v3.0) ###\n\
            Analyze this finding based on modern TTPs. Be extremely technical.\n\n\
            Target: {}\n\
            {}Finding: {}\n\n\
            JSON Schema: {{ \"summary\": \"...\", \"impact\": \"...\", \"stealth_notes\": \"...\", \"risk_score\": 1-10, \"confidence\": 0.0-1.0, \"mitre_attack\": [\"T1234\"], \"remediation\": \"...\", \"model\": \"{}\" }}",
            target.host, ctx_header, serde_json::to_string(&compressed)?, self.model
        );

        let client = self.get_client().await?;
        let res: serde_json::Value = client.post(format!("{}/api/generate", self.url))
            .json(&json!({ "model": self.model, "prompt": prompt, "stream": false, "format": "json" }))
            .send().await?.json().await?;

        let response_text = res["response"].as_str().context("Ollama response missing text")?;
        let mut analysis: AIAnalysis = serde_json::from_str(extract_json(response_text))?;
        
        if let Some(prompt_tokens) = res["prompt_eval_count"].as_u64() {
            analysis.usage.prompt_tokens = prompt_tokens as u32;
        }
        if let Some(completion_tokens) = res["eval_count"].as_u64() {
            analysis.usage.completion_tokens = completion_tokens as u32;
        }
        analysis.usage.total_tokens = analysis.usage.prompt_tokens + analysis.usage.completion_tokens;
        
        Ok(analysis)
    }

    async fn decide_action(
        &self, 
        finding: &Finding, 
        target: &TargetHost,
        plugins: &[crate::plugins::PluginMetadata],
        attack_context: Option<&str>,
        _gap: Option<&CapabilityGap>,
        adaptive_context: Option<&AdaptiveContext>,
        route_level: RouteLevel,
    ) -> Result<Option<(String, serde_json::Value)>> {
        let compressed_finding = ContextCompressor::compress_finding(finding, route_level);
        let compressed_plugins = ContextCompressor::compress_plugins(plugins);
        let adaptive_json = serde_json::to_string(&adaptive_context)?;
        let ctx_header = attack_context.map(|c| format!("Tactical Path: {}\n", c)).unwrap_or_default();

        let prompt = format!(
            "### SENTINEL ADAPTIVE ORCHESTRATOR ###\n\
            Target: {}\n\
            {}Current Finding: {}\n\
            Adaptive Context (RETRIES/BYPASSES): {}\n\
            Plugins: {}\n\n\
            Decision instructions: If previous actions failed/blocked, suggest a bypass action (different User-Agent, headers, or a different tool).\n\
            Return JSON: {{ \"action\": \"plugin_name\", \"tactical_context\": {{ \"user_agent\": \"...\", \"headers\": {{...}} }} }}",
            target.host, ctx_header, serde_json::to_string(&compressed_finding)?, adaptive_json, serde_json::to_string(&compressed_plugins)?
        );

        let client = self.get_client().await?;
        let res: serde_json::Value = client.post(format!("{}/api/generate", self.url))
            .json(&json!({ "model": self.model, "prompt": prompt, "stream": false, "format": "json" }))
            .send().await?.json().await?;

        let text = res["response"].as_str().context("Ollama decision missing text")?;
        let json_val: serde_json::Value = serde_json::from_str(extract_json(text))?;
        let action = json_val["action"].as_str().unwrap_or("none");
        
        if action == "none" || !plugins.iter().any(|p| p.name == action) {
             Ok(None)
        } else {
             Ok(Some((action.to_string(), json_val["tactical_context"].clone())))
        }
    }
}
