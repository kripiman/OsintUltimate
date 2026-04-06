use crate::models::{Finding, AIAnalysis, TargetHost};
use crate::core::pipeline::Pipeline;
use crate::core::ai_cascade::{ContextCompressor, AdaptiveContext};
use anyhow::{Result, Context};
use serde_json::json;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{info, warn, error};
use async_trait::async_trait;
use std::time::Duration;

#[async_trait]
pub trait LlmClient: Send + Sync {
    async fn analyze(&self, finding: &Finding, target: &TargetHost, route_level: crate::core::ai_cascade::RouteLevel) -> Result<AIAnalysis>;
    async fn decide_action(
        &self, 
        finding: &Finding, 
        target: &TargetHost,
        plugins: &[crate::plugins::PluginMetadata],
        gap: Option<&CapabilityGap>,
        adaptive_context: Option<&AdaptiveContext>,
        route_level: crate::core::ai_cascade::RouteLevel,
    ) -> Result<Option<(String, serde_json::Value)>>;
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CapabilityGap {
    pub covered_capabilities: std::collections::HashSet<crate::plugins::Capability>,
    pub recommended_capabilities: Vec<crate::plugins::Capability>,
}

pub struct OllamaClient {
    url: String,
    model: String,
    client: reqwest::Client,
}

impl OllamaClient {
    pub fn new(url: String, model: String) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .context("Failed to build Ollama client")?;
        Ok(Self { url, model, client })
    }
}

#[async_trait]
impl LlmClient for OllamaClient {
    async fn analyze(&self, finding: &Finding, target: &TargetHost, route_level: crate::core::ai_cascade::RouteLevel) -> Result<AIAnalysis> {
        let compressed = ContextCompressor::compress_finding(finding, route_level);
        let prompt = format!(
            "### PROFESSIONAL RED TEAM ENGINE (v3.0) ###\n\
            Analyze this finding based on modern TTPs. Be extremely technical.\n\n\
            Target: {}\n\
            Finding: {}\n\n\
            JSON Schema: {{ \"summary\": \"...\", \"impact\": \"...\", \"stealth_notes\": \"...\", \"risk_score\": 1-10, \"confidence\": 0.0-1.0, \"mitre_attack\": [\"T1234\"], \"remediation\": \"...\", \"model\": \"{}\" }}",
            target.host, serde_json::to_string(&compressed)?, self.model
        );

        let res = self.client.post(format!("{}/api/generate", self.url))
            .json(&json!({ "model": self.model, "prompt": prompt, "stream": false, "format": "json" }))
            .send().await?.json::<serde_json::Value>().await?;

        let response_text = res["response"].as_str().context("Ollama response missing text")?;
        let mut analysis: AIAnalysis = serde_json::from_str(extract_json(response_text))?;
        
        // Ollama token usage (eval_count, prompt_eval_count)
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
        _gap: Option<&CapabilityGap>,
        adaptive_context: Option<&AdaptiveContext>,
        route_level: crate::core::ai_cascade::RouteLevel,
    ) -> Result<Option<(String, serde_json::Value)>> {
        let compressed_finding = ContextCompressor::compress_finding(finding, route_level);
        let compressed_plugins = ContextCompressor::compress_plugins(plugins);
        let adaptive_json = serde_json::to_string(&adaptive_context)?;

        let prompt = format!(
            "### SENTINEL ADAPTIVE ORCHESTRATOR ###\n\
            Target: {}\n\
            Current Finding: {}\n\
            Adaptive Context (RETRIES/BYPASSES): {}\n\
            Plugins: {}\n\n\
            Decision instructions: If previous actions failed/blocked, suggest a bypass action (different User-Agent, headers, or a different tool).\n\
            Return JSON: {{ \"action\": \"plugin_name\", \"tactical_context\": {{ \"user_agent\": \"...\", \"headers\": {{...}} }} }}",
            target.host, serde_json::to_string(&compressed_finding)?, adaptive_json, serde_json::to_string(&compressed_plugins)?
        );

        let res = self.client.post(format!("{}/api/generate", self.url))
            .json(&json!({ "model": self.model, "prompt": prompt, "stream": false, "format": "json" }))
            .send().await?.json::<serde_json::Value>().await?;

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

pub struct GeminiClient {
    keys: Vec<String>,
    current_key_idx: std::sync::atomic::AtomicUsize,
    model: String,
    client: reqwest::Client,
}

impl GeminiClient {
    pub fn new(keys: Vec<String>, model: String) -> Result<Self> {
        if keys.is_empty() { anyhow::bail!("GeminiClient requires keys"); }
        let client = reqwest::Client::builder().timeout(Duration::from_secs(60)).build()?;
        Ok(Self { keys, current_key_idx: std::sync::atomic::AtomicUsize::new(0), model, client })
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
    async fn analyze(&self, finding: &Finding, target: &TargetHost, route_level: crate::core::ai_cascade::RouteLevel) -> Result<AIAnalysis> {
        let compressed = ContextCompressor::compress_finding(finding, route_level);
        let prompt = format!("Analyze this Red Team finding: {}. Target: {}. Provide JSON.", serde_json::to_string(&compressed)?, target.host);
        
        let mut last_error = None;
        for _ in 0..self.keys.len() {
            let url = format!("https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent?key={}", self.model, self.get_key());
            match self.client.post(url).json(&json!({ "contents": [{ "parts": [{ "text": prompt }] }], "generationConfig": { "response_mime_type": "application/json" } })).send().await {
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

    async fn decide_action(&self, finding: &Finding, target: &TargetHost, plugins: &[crate::plugins::PluginMetadata], _gap: Option<&CapabilityGap>, adaptive_context: Option<&AdaptiveContext>, route_level: crate::core::ai_cascade::RouteLevel) -> Result<Option<(String, serde_json::Value)>> {
        let compressed = ContextCompressor::compress_finding(finding, route_level);
        let prompt = format!("Decide next step for {}. History: {:?}. Finding: {}. Plugins: {}. Focus on WAF bypass.", target.host, adaptive_context, finding.id, plugins.len());
        
        for _ in 0..self.keys.len() {
            let url = format!("https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent?key={}", self.model, self.get_key());
            match self.client.post(url).json(&json!({ "contents": [{ "parts": [{ "text": prompt }] }], "generationConfig": { "response_mime_type": "application/json" } })).send().await {
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

pub struct AzureOpenAIClient {
    endpoint: String,
    key: String,
    deployment: String,
    api_version: String,
    client: reqwest::Client,
}

impl AzureOpenAIClient {
    pub fn new(endpoint: String, key: String, deployment: String, api_version: String) -> Result<Self> {
        let client = reqwest::Client::builder().timeout(Duration::from_secs(60)).build()?;
        Ok(Self { endpoint, key, deployment, api_version, client })
    }
}

#[async_trait]
impl LlmClient for AzureOpenAIClient {
    async fn analyze(&self, finding: &Finding, target: &TargetHost, route_level: crate::core::ai_cascade::RouteLevel) -> Result<AIAnalysis> {
        let compressed = ContextCompressor::compress_finding(finding, route_level);
        let url = format!("{}/openai/deployments/{}/chat/completions?api-version={}", self.endpoint, self.deployment, self.api_version);
        let res = self.client.post(url).header("api-key", &self.key).json(&json!({
            "messages": [{ "role": "system", "content": "Return strictly JSON analysis." }, { "role": "user", "content": format!("Target: {}, Finding: {}", target.host, serde_json::to_string(&compressed)?) }],
            "response_format": { "type": "json_object" }
        })).send().await?.json::<serde_json::Value>().await?;
        let text = res["choices"][0]["message"]["content"].as_str().context("Azure error")?;
        Ok(serde_json::from_str(extract_json(text))?)
    }

    async fn decide_action(&self, finding: &Finding, target: &TargetHost, plugins: &[crate::plugins::PluginMetadata], _gap: Option<&CapabilityGap>, adaptive_context: Option<&AdaptiveContext>, route_level: crate::core::ai_cascade::RouteLevel) -> Result<Option<(String, serde_json::Value)>> {
        let compressed = ContextCompressor::compress_finding(finding, route_level);
        let url = format!("{}/openai/deployments/{}/chat/completions?api-version={}", self.endpoint, self.deployment, self.api_version);
        let res = self.client.post(url).header("api-key", &self.key).json(&json!({
            "messages": [
                { "role": "system", "content": "Return JSON: {\"action\": \"name\", \"tactical_context\": {}}" },
                { "role": "user", "content": format!("Target: {}, Finding: {}, Context: {:?}", target.host, finding.id, adaptive_context) }
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

pub struct AnthropicClient {
    key: String,
    model: String,
    client: reqwest::Client,
}

impl AnthropicClient {
    pub fn new(key: String, model: String) -> Result<Self> {
        let client = reqwest::Client::builder().timeout(Duration::from_secs(60)).build()?;
        Ok(Self { key, model, client })
    }
}

#[async_trait]
impl LlmClient for AnthropicClient {
    async fn analyze(&self, finding: &Finding, target: &TargetHost, route_level: crate::core::ai_cascade::RouteLevel) -> Result<AIAnalysis> {
        let compressed = ContextCompressor::compress_finding(finding, route_level);
        let res = self.client.post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", &self.key)
            .header("anthropic-version", "2023-06-01")
            .json(&json!({
                "model": self.model,
                "max_tokens": 1024,
                "messages": [{ "role": "user", "content": format!("Analyze this: {}. Target: {}", serde_json::to_string(&compressed)?, target.host) }],
            })).send().await?.json::<serde_json::Value>().await?;
        
        let text = res["content"][0]["text"].as_str().context("Anthropic error")?;
        Ok(serde_json::from_str(extract_json(text))?)
    }

    async fn decide_action(&self, finding: &Finding, target: &TargetHost, plugins: &[crate::plugins::PluginMetadata], _gap: Option<&CapabilityGap>, adaptive_context: Option<&AdaptiveContext>, route_level: crate::core::ai_cascade::RouteLevel) -> Result<Option<(String, serde_json::Value)>> {
        Ok(None)
    }
}

pub struct OpenAIClient {
    key: String,
    model: String,
    client: reqwest::Client,
}

impl OpenAIClient {
    pub fn new(key: String, model: String) -> Result<Self> {
        let client = reqwest::Client::builder().timeout(Duration::from_secs(60)).build()?;
        Ok(Self { key, model, client })
    }
}

#[async_trait]
impl LlmClient for OpenAIClient {
    async fn analyze(&self, finding: &Finding, target: &TargetHost, route_level: crate::core::ai_cascade::RouteLevel) -> Result<AIAnalysis> {
        let compressed = ContextCompressor::compress_finding(finding, route_level);
        let res = self.client.post("https://api.openai.com/v1/chat/completions")
            .header("Authorization", format!("Bearer {}", self.key))
            .json(&json!({
                "model": self.model,
                "messages": [{ "role": "user", "content": format!("Analyze this: {}. Target: {}", serde_json::to_string(&compressed)?, target.host) }],
                "response_format": { "type": "json_object" }
            })).send().await?.json::<serde_json::Value>().await?;
        
        let text = res["choices"][0]["message"]["content"].as_str().context("OpenAI error")?;
        Ok(serde_json::from_str(extract_json(text))?)
    }

    async fn decide_action(&self, finding: &Finding, target: &TargetHost, plugins: &[crate::plugins::PluginMetadata], _gap: Option<&CapabilityGap>, adaptive_context: Option<&AdaptiveContext>, route_level: crate::core::ai_cascade::RouteLevel) -> Result<Option<(String, serde_json::Value)>> {
        Ok(None)
    }
}

pub struct AutonomousAgent {
    router: Arc<crate::core::ai_cascade::TieredAIRouter>,
    pipeline: Arc<Pipeline>,
    approval_gate: Arc<crate::core::approval_gate::ApprovalGate>,
    operator: crate::core::approval_gate::User,
    poc_validator: Arc<crate::core::poc_validator::PocValidator>,
}

impl AutonomousAgent {
    pub fn new(router: Arc<crate::core::ai_cascade::TieredAIRouter>, pipeline: Arc<Pipeline>, approval_gate: Arc<crate::core::approval_gate::ApprovalGate>) -> Self {
        let operator = crate::core::approval_gate::User {
            id: "sentinel-agent".to_string(),
            name: "Sentinel-AI".to_string(),
            role: crate::core::approval_gate::UserRole::RedTeamFull,
            authorized_at: chrono::Utc::now(),
        };
        let poc_validator = Arc::new(crate::core::poc_validator::PocValidator::new(
            router.clone(),
            approval_gate.clone(),
            operator.clone(),
        ));
        Self { router, pipeline, approval_gate, operator, poc_validator }
    }

    pub async fn run_autopilot(&self, initial_target: TargetHost, sink_tx: mpsc::Sender<TargetHost>) -> Result<()> {
        info!("🤖 SENTINEL: Iniciando ciclo autónomo adaptativo para {}", initial_target.host);
        let mut seen_finding_ids = std::collections::HashSet::new();
        let mut adaptive_context = AdaptiveContext::default();
        let mut correlation_engine = crate::core::CorrelationEngine::new();
        let (tx, mut rx) = mpsc::channel(100);
        let pipeline = Arc::clone(&self.pipeline);
        let target = initial_target.clone();
        let tx_discovery = tx.clone();
        tokio::spawn(async move { let _ = pipeline.run_discovery(&target, tx_discovery).await; });

        while let Some(finding) = rx.recv().await {
            if seen_finding_ids.contains(&finding.id) { continue; }
            seen_finding_ids.insert(finding.id.clone());
            
            // Add to correlation engine
            correlation_engine.add_finding(finding.clone());
            
            let analysis = self.router.analyze(&finding, &initial_target).await?;
            let mut final_finding = finding.with_ai_analysis(analysis.clone()).with_remediation(&analysis.remediation);
            if let Some(tags) = analysis.mitre_attack { final_finding = final_finding.with_mitre_attack(tags); }
            
            // --- POC VALIDATION PIPELINE ---
            if analysis.risk_score >= 8 || final_finding.severity == crate::models::Severity::High || final_finding.severity == crate::models::Severity::Critical {
                info!("🧪 SENTINEL: Detectado hallazgo crítico/alto. Iniciando pipeline de validación de PoC...");
                let _ = self.poc_validator.validate(&mut final_finding, &initial_target).await;
            }

            let mut sink_target = initial_target.clone();
            sink_target.findings = Arc::new(vec![final_finding.clone()]);
            let paths = correlation_engine.get_attack_paths();
            if !paths.is_empty() {
                 Arc::make_mut(&mut sink_target.extra_data)["attack_paths"] = serde_json::json!(paths);
            }
            let _ = sink_tx.send(sink_target).await;

            let metadata = self.pipeline.get_plugin_metadata();
            if let Ok(Some((action, tactical))) = self.router.decide_action(&final_finding, &initial_target, &metadata, Some(&adaptive_context)).await {
                if self.request_operator_approval(&action).await {
                    let mut task_target = initial_target.clone();
                    task_target.tactical_context = Arc::new(tactical.clone());
                    adaptive_context.previous_actions.push(action.clone());
                    let results = self.pipeline.run_specific_plugin(&action, &task_target).await?;
                    if results.is_empty() {
                         adaptive_context.block_count += 1;
                         adaptive_context.was_detected = true;
                    } else {
                         adaptive_context.was_detected = false;
                         for nf in results { let _ = tx.send(nf).await; }
                    }
                }
            }
            if adaptive_context.previous_actions.len() > 50 { break; }
        }
        Ok(())
    }

    async fn request_operator_approval(&self, action: &str) -> bool {
        if self.approval_gate.is_approved(action).await { return true; }
        match self.approval_gate.request_approval(action, 85, &self.operator, "Autonomous Adaptive Loop").await {
            Ok(None) => true,
            _ => false,
        }
    }
}

fn extract_json(text: &str) -> &str {
    if let Some(start) = text.find('{') {
        if let Some(end) = text.rfind('}') { return &text[start..=end]; }
    }
    text
}
