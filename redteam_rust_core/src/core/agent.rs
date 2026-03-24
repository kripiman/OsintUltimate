use crate::models::{Finding, AIAnalysis, TargetHost};
use crate::core::pipeline::Pipeline;
use anyhow::{Result, Context};
use serde_json::json;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{info, warn, error};
use async_trait::async_trait;

#[async_trait]
pub trait LlmClient: Send + Sync {
    async fn analyze(&self, finding: &Finding) -> Result<AIAnalysis>;
    async fn decide_action(&self, finding: &Finding, plugins: &[crate::plugins::PluginMetadata]) -> Result<Option<String>>;
}

pub struct OllamaClient {
    url: String,
    model: String,
}

impl OllamaClient {
    pub fn new(url: String, model: String) -> Self {
        Self { url, model }
    }
}

#[async_trait]
impl LlmClient for OllamaClient {
    async fn analyze(&self, finding: &Finding) -> Result<AIAnalysis> {
        let client = reqwest::Client::new();
        let prompt = format!(
            "### PROFESSIONAL RED TEAM ANALYSIS ###\n\
            Analyze this finding from an architectural and modern pentesting perspective. Provide a deep analysis in JSON.\n\n\
            Finding: {}\n\
            Description: {}\n\
            Evidencia: {:?}\n\n\
            JSON Schema: {{ \"summary\": \"...\", \"impact\": \"...\", \"stealth_notes\": \"...\", \"risk_score\": 1-10, \"confidence\": 0.0-1.0, \"mitre_attack\": [\"T1234\", ...], \"remediation\": \"Clear architectural fix\", \"model\": \"{}\" }}",
            finding.id, finding.description, finding.evidence.data, self.model
        );

        let res = client.post(format!("{}/api/generate", self.url))
            .json(&json!({
                "model": self.model,
                "prompt": prompt,
                "stream": false,
                "format": "json"
            }))
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;

        let response_text = res["response"].as_str().context("Ollama response missing text")?;
        let json_text = extract_json(response_text);
        let analysis: AIAnalysis = serde_json::from_str(json_text)?;
        Ok(analysis)
    }

    async fn decide_action(&self, finding: &Finding, plugins: &[crate::plugins::PluginMetadata]) -> Result<Option<String>> {
        let client = reqwest::Client::new();
        let plugins_json = serde_json::to_string(plugins)?;
        let prompt = format!(
            "Basado en este hallazgo, ¿cuál es el mejor siguiente paso? Plugins disponibles (JSON): {}\n\
            Hallazgo: {}\n\
            Responde SOLO con el nombre del plugin or 'none' en formato JSON: {{ \"action\": \"plugin_name\" }}",
            plugins_json, finding.description
        );

        let res = client.post(format!("{}/api/generate", self.url))
            .json(&json!({
                "model": self.model,
                "prompt": prompt,
                "stream": false,
                "format": "json"
            }))
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;

        let text = res["response"].as_str().context("Ollama decision missing text")?;
        let json_val: serde_json::Value = serde_json::from_str(extract_json(text))?;
        let action = json_val["action"].as_str().unwrap_or("none");
        
        if action == "none" || !plugins.iter().any(|p| p.name == action) {
            Ok(None)
        } else {
            Ok(Some(action.to_string()))
        }
    }
}

pub struct GeminiClient {
    key: String,
    model: String,
}

impl GeminiClient {
    pub fn new(key: String, model: String) -> Self {
        Self { key, model }
    }
}

#[async_trait]
impl LlmClient for GeminiClient {
    async fn analyze(&self, finding: &Finding) -> Result<AIAnalysis> {
        let client = reqwest::Client::new();
        let prompt = format!(
            "### PROFESSIONAL RED TEAM ANALYSIS ###\n\
            Analyze this finding from an architectural and modern pentesting perspective. Provide a deep analysis in JSON.\n\n\
            Finding: {}\n\
            Category: {:?}\n\
            Severity: {:?}\n\
            Description: {}\n\
            Evidence: {:?}\n\n\
            JSON Schema: {{\n\
                \"summary\": \"Brief executive summary\",\n\
                \"impact\": \"Detailed business and technical impact\",\n\
                \"stealth_notes\": \"Operational security recommendations for avoiding detection\",\n\
                \"risk_score\": 1-10,\n\
                \"confidence\": 0.0-1.0,\n\
                \"mitre_attack\": [\"T1190\", \"T1595\", ...],\n\
                \"remediation\": \"Clear architectural fix recommendation\",\n\
                \"model\": \"{}\"\n\
            }}",
            finding.id, finding.category, finding.severity, finding.description, finding.evidence.data, self.model
        );

        let url = format!("https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent?key={}", self.model, self.key);
        
        let res = client.post(url)
            .json(&json!({
                "contents": [{ "parts": [{ "text": prompt }] }],
                "generationConfig": { "response_mime_type": "application/json" }
            }))
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;

        let text = res["candidates"][0]["content"]["parts"][0]["text"].as_str().context("Gemini response error")?;
        let analysis: AIAnalysis = serde_json::from_str(extract_json(text))?;
        Ok(analysis)
    }

    async fn decide_action(&self, finding: &Finding, plugins: &[crate::plugins::PluginMetadata]) -> Result<Option<String>> {
        let client = reqwest::Client::new();
        let plugins_json = serde_json::to_string(plugins)?;
        let prompt = format!(
            "### SENTINEL ORCHESTRATOR LOOP ###\n\
            Based on the current finding, decide which tool to execute next. Favor tools that fulfill missing capabilities.\n\n\
            Finding: {}\n\
            Plugins Available (Metadata & Capabilities): {}\n\n\
            Respond ONLY with the name of the plugin or 'none' in JSON: {{ \"action\": \"plugin_name\" }}",
            finding.description, plugins_json
        );

        let url = format!("https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent?key={}", self.model, self.key);
        
        let res = client.post(url)
            .json(&json!({
                "contents": [{ "parts": [{ "text": prompt }] }],
                "generationConfig": { "response_mime_type": "application/json" }
            }))
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;

        let text = res["candidates"][0]["content"]["parts"][0]["text"].as_str().context("Gemini decision error")?;
        let json_val: serde_json::Value = serde_json::from_str(extract_json(text))?;
        let action = json_val["action"].as_str().unwrap_or("none");
        
        if action == "none" || !plugins.iter().any(|p| p.name == action) {
            Ok(None)
        } else {
            Ok(Some(action.to_string()))
        }
    }
}

pub struct AutonomousAgent {
    llm: Arc<dyn LlmClient>,
    pipeline: Arc<Pipeline>,
}

impl AutonomousAgent {
    pub fn new(llm: Arc<dyn LlmClient>, pipeline: Arc<Pipeline>) -> Self {
        Self { llm, pipeline }
    }

    pub async fn run_autopilot(&self, initial_target: TargetHost) -> Result<Vec<Finding>> {
        info!("🤖 SENTINEL: Iniciando ciclo autónomo para {}", initial_target.host);
        let mut all_findings = Vec::new();
        let (tx, mut rx) = mpsc::channel(100);

        // 1. Descubrimiento inicial
        let pipeline = Arc::clone(&self.pipeline);
        let target = initial_target.clone();
        tokio::spawn(async move {
            if let Err(e) = pipeline.run_discovery(&target, tx).await {
                error!("Sentinel: Discovery failed: {}", e);
            }
        });

        // 2. Bucle Observar-Pensar-Actuar
        while let Some(finding) = rx.recv().await {
            info!("Sentinel: Observando hallazgo: {}", finding.id);
            
            // Pensar: Análisis profundo
            let analysis = self.llm.analyze(&finding).await?;
            let mut finding = finding.with_ai_analysis(analysis.clone())
                                   .with_remediation(&analysis.remediation);
            if let Some(tags) = analysis.mitre_attack {
                finding = finding.with_mitre_attack(tags);
            }
            all_findings.push(finding.clone());

            // Decidir: Orquestación dinámica
            // Obtenemos metadatos de plugins disponibles para que la IA elija con contexto
            let available_metadata = self.pipeline.get_plugin_metadata(); 
            
            if let Some(next_action) = self.llm.decide_action(&finding, &available_metadata).await? {
                info!("Sentinel: IA decidió ejecutar acción: {}", next_action);
                
                if self.request_operator_approval(&next_action).await {
                    // Aquí ejecutamos el plugin específico decidido por la IA
                    let new_findings = self.pipeline.run_specific_plugin(&next_action, &initial_target).await?;
                    for nf in new_findings {
                        if !all_findings.iter().any(|f| f.id == nf.id) {
                            all_findings.push(nf);
                        }
                    }
                }
            }
        }

        Ok(all_findings)
    }

    async fn request_operator_approval(&self, action: &str) -> bool {
        info!("Sentinel: Solicitando aprobación para {}", action);
        // En un entorno profesional real, esto esperaría interacción humana vía TUI/Web
        true 
    }
}

fn extract_json(text: &str) -> &str {
    if let Some(start) = text.find('{') {
        if let Some(end) = text.rfind('}') {
            return &text[start..=end];
        }
    }
    text
}

