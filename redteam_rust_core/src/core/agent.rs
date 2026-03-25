use crate::models::{Finding, AIAnalysis, TargetHost};
use crate::core::pipeline::Pipeline;
use crate::core::ai_cascade::ContextCompressor;
use anyhow::{Result, Context};
use serde_json::json;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{info, warn, error};
use async_trait::async_trait;

#[async_trait]
pub trait LlmClient: Send + Sync {
    async fn analyze(&self, finding: &Finding) -> Result<AIAnalysis>;
    async fn decide_action(
        &self, 
        finding: &Finding, 
        plugins: &[crate::plugins::PluginMetadata],
        gap: Option<&CapabilityGap>
    ) -> Result<Option<String>>;
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CapabilityGap {
    pub covered_capabilities: std::collections::HashSet<crate::plugins::Capability>,
    pub recommended_capabilities: Vec<crate::plugins::Capability>,
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
        let compressed = ContextCompressor::compress_finding(finding);
        let prompt = format!(
            "### PROFESSIONAL RED TEAM ANALYSIS ###\n\
            Analyze this finding from an architectural and modern pentesting perspective. Provide a deep analysis in JSON.\n\n\
            Finding (Minified): {}\n\n\
            JSON Schema: {{ \"summary\": \"...\", \"impact\": \"...\", \"stealth_notes\": \"...\", \"risk_score\": 1-10, \"confidence\": 0.0-1.0, \"mitre_attack\": [\"T1234\", ...], \"remediation\": \"Clear architectural fix\", \"model\": \"{}\" }}",
            serde_json::to_string_pretty(&compressed)?, self.model
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

    async fn decide_action(
        &self, 
        finding: &Finding, 
        plugins: &[crate::plugins::PluginMetadata],
        gap: Option<&CapabilityGap>
    ) -> Result<Option<String>> {
        let client = reqwest::Client::new();
        let compressed_finding = ContextCompressor::compress_finding(finding);
        let compressed_plugins = ContextCompressor::compress_plugins(plugins);
        let gap_json = if let Some(g) = gap {
            serde_json::to_string(g)?
        } else {
            "{}".to_string()
        };

        let prompt = format!(
            "### SENTINEL ORCHESTRATOR ###\n\
            Basado en este hallazgo y el estado actual del escaneo, ¿cuál es el mejor siguiente paso?\n\n\
            Estado del Escaneo (Gaps): {}\n\
            Hallazgo Actual (Minified): {}\n\
            Plugins disponibles (Metadata): {}\n\n\
            Responde SOLO con el nombre del plugin or 'none' en formato JSON: {{ \"action\": \"plugin_name\" }}",
            gap_json, 
            serde_json::to_string(&compressed_finding)?, 
            serde_json::to_string(&compressed_plugins)?
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
        let compressed = ContextCompressor::compress_finding(finding);
        let prompt = format!(
            "### PROFESSIONAL RED TEAM ANALYSIS ###\n\
            Analyze this finding from an architectural and modern pentesting perspective. Provide a deep analysis in JSON.\n\n\
            Finding (Minified): {}\n\n\
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
            serde_json::to_string_pretty(&compressed)?, self.model
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

    async fn decide_action(
        &self, 
        finding: &Finding, 
        plugins: &[crate::plugins::PluginMetadata],
        gap: Option<&CapabilityGap>
    ) -> Result<Option<String>> {
        let client = reqwest::Client::new();
        let compressed_finding = ContextCompressor::compress_finding(finding);
        let compressed_plugins = ContextCompressor::compress_plugins(plugins);
        let gap_json = if let Some(g) = gap {
            serde_json::to_string(g)?
        } else {
            "{}".to_string()
        };

        let prompt = format!(
            "### SENTINEL ORCHESTRATOR LOOP ###\n\
            Based on the current finding and scan state, decide which tool to execute next. Favor tools that fulfill missing capabilities.\n\n\
            Scan Gaps/Context: {}\n\
            Current Finding (Minified): {}\n\
            Plugins Available (Minified): {}\n\n\
            Respond ONLY with the name of the plugin or 'none' in JSON: {{ \"action\": \"plugin_name\" }}",
            gap_json, 
            serde_json::to_string(&compressed_finding)?, 
            serde_json::to_string(&compressed_plugins)?
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
    router: Arc<crate::core::ai_cascade::TieredAIRouter>,
    pipeline: Arc<Pipeline>,
    approval_gate: Arc<crate::core::approval_gate::ApprovalGate>,
    operator: crate::core::approval_gate::User,
}

impl AutonomousAgent {
    pub fn new(
        router: Arc<crate::core::ai_cascade::TieredAIRouter>, 
        pipeline: Arc<Pipeline>, 
        approval_gate: Arc<crate::core::approval_gate::ApprovalGate>
    ) -> Self {
        let operator = crate::core::approval_gate::User {
            id: "sentinel-agent".to_string(),
            name: "Sentinel-AI".to_string(),
            role: crate::core::approval_gate::UserRole::RedTeamFull,
            authorized_at: chrono::Utc::now(),
        };

        Self { router, pipeline, approval_gate, operator }
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
            
            // Pensar: Análisis profundo vía Tiered Router
            let analysis = self.router.analyze(&finding).await?;
            let mut finding = finding.with_ai_analysis(analysis.clone())
                                   .with_remediation(&analysis.remediation);
            if let Some(tags) = analysis.mitre_attack {
                finding = finding.with_mitre_attack(tags);
            }
            all_findings.push(finding.clone());

            // Decidir: Orquestación dinámica basada en Gaps de capacidades
            let available_metadata = self.pipeline.get_plugin_metadata(); 
            
            // ARCH-1 Improvement: Calculate capability gap to prompt better decisions
            let gap = self.calculate_capability_gap(&all_findings);
            
            if let Some(next_action) = self.router.decide_action(&finding, &available_metadata).await? {
                info!("Sentinel: IA decidió ejecutar acción: {} para cubrir gaps: {:?}", next_action, gap.recommended_capabilities);
                
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

    fn calculate_capability_gap(&self, current_findings: &[Finding]) -> CapabilityGap {
        use std::collections::HashSet;
        let mut covered = HashSet::new();
        
        // Categorías de hallazgos que inferencialmente cubren capacidades
        for f in current_findings {
            match f.category {
                crate::models::Category::Vulnerability => { covered.insert(crate::plugins::Capability::VulnerabilityScanning); }
                crate::models::Category::NetworkPort => { covered.insert(crate::plugins::Capability::PortScanning); }
                crate::models::Category::Misconfiguration => { 
                    covered.insert(crate::plugins::Capability::ConfigAudit);
                    covered.insert(crate::plugins::Capability::SecurityAuditing);
                }
                _ => {}
            }
        }

        // Recomendaciones tácticas
        let mut recommended = Vec::new();
        if !covered.contains(&crate::plugins::Capability::VulnerabilityScanning) {
            recommended.push(crate::plugins::Capability::VulnerabilityScanning);
        }
        if !covered.contains(&crate::plugins::Capability::ServiceDiscovery) {
            recommended.push(crate::plugins::Capability::ServiceDiscovery);
        }

        CapabilityGap {
            covered_capabilities: covered,
            recommended_capabilities: recommended,
        }
    }

    async fn request_operator_approval(&self, action: &str) -> bool {
        info!("🤖 Sentinel: Requesting risk approval for action: {}", action);

        // Check if already approved (e.g. by a previous manual bypass or higher policy)
        if self.approval_gate.is_approved(action).await {
            return true;
        }

        // Logic: All autonomous exploitation actions (layer 4+) should be routed to the Gate.
        // We use a risk score of 85 by default for tactical AI decisions.
        match self.approval_gate.request_approval(
            action, 
            85, 
            &self.operator, 
            "Autonomous Red Team Orchestration Loop"
        ).await {
            Ok(approved) => {
                if approved {
                    info!("✅ Approval granted for {}", action);
                } else {
                    warn!("⏳ Action {} is PENDING approval in the Gate.", action);
                }
                approved
            }
            Err(e) => {
                error!("❌ Approval system error: {}", e);
                false
            }
        }
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

