use anyhow::Result;
use async_trait::async_trait;
use crate::models::AIAnalysis;
use crate::core::ai::traits::LlmClient;
use crate::core::ai::compressor::ContextCompressor;
use crate::core::ai::cli_llm::{CliLlmConfig, run_cli_prompt};
use crate::core::ai::templates::{SYSTEM_ANALYSIS, SYSTEM_DECISION};
use std::sync::Arc;

pub struct KimiCliClient {
    pub base: super::base::BaseLlmClient,
    pub config: CliLlmConfig,
}

impl KimiCliClient {
    pub fn new(pm: Arc<crate::utils::proxy::ProxyManager>) -> Result<Self> {
        let binary = std::env::var("KIMI_CLI_BIN").unwrap_or_else(|_| "kimi".to_string());
        let timeout_secs = std::env::var("KIMI_CLI_TIMEOUT_SECS")
            .ok()
            .and_then(|s| match s.parse::<u64>() {
                Ok(v) => Some(v),
                Err(e) => { tracing::warn!("Invalid KIMI_CLI_TIMEOUT_SECS={}, falling back to 60. err={}", s, e); None }
            })
            .unwrap_or(60);
        Ok(Self {
            base: super::base::BaseLlmClient::new(pm),
            config: CliLlmConfig {
                binary,
                prompt_flag: "--prompt",
                quiet_flag: Some("--quiet"),
                timeout_secs,
            },
        })
    }
}

#[async_trait]
impl LlmClient for KimiCliClient {
    async fn analyze(&self, config: crate::core::ai::traits::InferenceConfig<'_>) -> Result<AIAnalysis> {
        let compressed = ContextCompressor::compress_finding(config.finding, config.route_level);
        let ctx = config.attack_context.map(|c| format!(" Tactical Path: {}.", c)).unwrap_or_default();
        let prompt_raw = format!("Analyze this: {}. Target: {}.{}", serde_json::to_string(&compressed)?, config.target.host, ctx);
        let prompt = crate::core::ai::caveman::CavemanOptimizer::optimize_prompt(&prompt_raw, config.caveman);
        let text = run_cli_prompt(&self.config, SYSTEM_ANALYSIS, &prompt).await?;
        Ok(serde_json::from_value(self.base.parse_extraction(&text)?)?)
    }

    async fn decide_action(&self, config: crate::core::ai::traits::DecisionConfig<'_>) -> Result<Option<(String, serde_json::Value)>> {
        let ctx_header = config.attack_context.map(|c| format!("Tactical Path: {}\n", c)).unwrap_or_default();
        let prompt_raw = format!("{}Decide next step for {}. History: {:?}. Finding: {}. Plugins: {}. Focus on WAF bypass. Return JSON with 'action' (must match a plugin name exactly or 'none') and 'tactical_context' (JSON object).", ctx_header, config.target.host, config.adaptive_context, config.finding.id, config.plugins.len());
        let prompt = crate::core::ai::caveman::CavemanOptimizer::optimize_prompt(&prompt_raw, config.caveman);
        let text = run_cli_prompt(&self.config, SYSTEM_DECISION, &prompt).await?;
        if text.trim().is_empty() { return Ok(None); }
        if let Ok(json_val) = self.base.parse_extraction(&text) {
            let action = json_val["action"].as_str().unwrap_or("none");
            if action == "none" || !config.plugins.iter().any(|p| p.name == action) { return Ok(None); }
            return Ok(Some((action.to_string(), json_val["tactical_context"].clone())));
        }
        Ok(None)
    }
}
