use anyhow::{Result, Context};
use async_trait::async_trait;
use crate::models::AIAnalysis;
use crate::core::ai::traits::LlmClient;
use crate::core::ai::compressor::ContextCompressor;
use std::sync::Arc;
use tokio::process::Command;

pub struct ClaudeCodeClient {
    pub base: super::base::BaseLlmClient,
}

impl ClaudeCodeClient {
    pub fn new(pm: Arc<crate::utils::proxy::ProxyManager>) -> Result<Self> {
        Ok(Self { 
            base: super::base::BaseLlmClient::new(pm),
        })
    }
}

#[async_trait]
impl LlmClient for ClaudeCodeClient {
    async fn analyze(&self, config: crate::core::ai::traits::InferenceConfig<'_>) -> Result<AIAnalysis> {
        let compressed = ContextCompressor::compress_finding(config.finding, config.route_level);
        let ctx = config.attack_context.map(|c| format!(" Tactical Path: {}.", c)).unwrap_or_default();
        let prompt_raw = format!("Analyze this: {}. Target: {}.{}", serde_json::to_string(&compressed)?, config.target.host, ctx);
        let prompt = crate::core::ai::caveman::CavemanOptimizer::optimize_prompt(&prompt_raw, config.caveman);
        
        let full_prompt = format!("### PROFESSIONAL RED TEAM ENGINE ###\nReturn strictly JSON. You must include these fields: 'summary', 'impact', 'stealth_notes', 'risk_score', 'confidence', 'mitre_attack', 'exploit_path', 'model'. DO NOT output defensive remediations or fixes; provide the exploit path.\n\n{}", prompt);
        
        let output = Command::new("claude")
            .arg("-p")
            .arg(&full_prompt)
            .output()
            .await
            .context("Failed to execute claude code CLI. Ensure 'claude' is in PATH")?;

        let text = String::from_utf8_lossy(&output.stdout).to_string();
        
        if text.trim().is_empty() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Claude CLI returned empty output. Error: {}", stderr);
        }

        Ok(serde_json::from_value(self.base.parse_extraction(&text)?)?)
    }

    async fn decide_action(&self, config: crate::core::ai::traits::DecisionConfig<'_>) -> Result<Option<(String, serde_json::Value)>> {
        let _ = crate::core::ai::compressor::ContextCompressor::compress_finding(config.finding, config.route_level);
        let ctx_header = config.attack_context.map(|c| format!("Tactical Path: {}\n", c)).unwrap_or_default();
        let prompt_raw = format!("### SENTINEL ORCHESTRATOR ###\n{}Decide next step for {}. History: {:?}. Finding: {}. Plugins: {}. Focus on WAF bypass. Return JSON with 'action' (must match a plugin name exactly or 'none') and 'tactical_context' (JSON object).", ctx_header, config.target.host, config.adaptive_context, config.finding.id, config.plugins.len());
        let prompt = crate::core::ai::caveman::CavemanOptimizer::optimize_prompt(&prompt_raw, config.caveman);
        
        let full_prompt = format!("You are a Sentinel Orchestrator. Return strictly JSON with 'action' and 'tactical_context'.\n\n{}", prompt);
        
        let output = tokio::process::Command::new("claude")
            .arg("-p")
            .arg(&full_prompt)
            .output()
            .await
            .context("Failed to execute claude code CLI.")?;

        let text = String::from_utf8_lossy(&output.stdout).to_string();
        
        if text.trim().is_empty() { return Ok(None); }

        if let Ok(json_val) = self.base.parse_extraction(&text) {
            let action = json_val["action"].as_str().unwrap_or("none");
            if action == "none" || !config.plugins.iter().any(|p| p.name == action) { return Ok(None); }
            return Ok(Some((action.to_string(), json_val["tactical_context"].clone())));
        }
        Ok(None)
    }
}
