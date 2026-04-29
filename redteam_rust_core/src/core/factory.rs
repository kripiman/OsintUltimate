use std::sync::Arc;
use anyhow::Result;
use crate::core::ai::{TieredAIRouter, RouteLevel, LlmProviderKind};
use crate::core::ai::{OllamaClient, GeminiClient, AnthropicClient, OpenAIClient, AzureOpenAIClient, AntigravityClient, KimiClient, ClaudeCodeClient};
use crate::utils::{InfrastructureType, HardwareInfo, proxy::ProxyManager};

pub struct EngineFactory;

impl EngineFactory {
    /// Detect infrastructure and return auto-adjusted concurrency limits
    pub fn detect_infrastructure_limits() -> (HardwareInfo, usize, usize, usize) {
        let hw = crate::utils::detect_infrastructure();
        
        let (concurrency, soft_limit, hard_limit) = match hw.infra_type {
            InfrastructureType::UltraLowMemory => (10, 500, 850),
            InfrastructureType::LocalPC => (30, 800, 1200),
            InfrastructureType::Hybrid => (60, 1200, 2000),
            InfrastructureType::Server => (150, 4000, 8000),
        };

        (hw, concurrency, soft_limit, hard_limit)
    }

    /// Build a pre-configured AI Router based on available environment variables
    pub fn build_default_router(ollama_url: String, pm: Arc<ProxyManager>) -> Result<Arc<TieredAIRouter>> {
        let mut router = TieredAIRouter::new();
        
        // Tier 0: Local (Ollama)
        router.add_provider(RouteLevel::Local, LlmProviderKind::Local, 0, Arc::new(OllamaClient::new(
            ollama_url,
            "qwen2.5-coder:7b".to_string(),
            pm.clone()
        )?));

        // Tier 1: Mid
        if let (Ok(endpoint), Ok(key)) = (std::env::var("AZURE_OPENAI_ENDPOINT"), std::env::var("AZURE_OPENAI_KEY")) {
            router.add_provider(RouteLevel::Mid, LlmProviderKind::AzureOpenAI, 0, Arc::new(AzureOpenAIClient::new(
                endpoint,
                key,
                "gpt-4o-mini".to_string(),
                "2024-02-01".to_string(),
                pm.clone()
            )?));
        }

        if let Ok(key) = std::env::var("OPENAI_API_KEY") {
            router.add_provider(RouteLevel::Mid, LlmProviderKind::OpenAI, 1, Arc::new(OpenAIClient::new(
                key,
                "gpt-4o-mini".to_string(),
                pm.clone()
            )?));
        }

        // Tier 2: Premium
        if let Ok(keys_str) = std::env::var("GEMINI_API_KEYS") {
            let keys: Vec<String> = keys_str.split(',').map(|k| k.trim().to_string()).filter(|k| !k.is_empty()).collect();
            if !keys.is_empty() {
                router.add_provider(RouteLevel::Premium, LlmProviderKind::Gemini, 0, Arc::new(GeminiClient::new(
                    keys, 
                    "gemini-1.5-pro".to_string(),
                    pm.clone()
                )?));
                
                // Also add Flash for Mid-tier if Gemini is available
                router.add_provider(RouteLevel::Mid, LlmProviderKind::Gemini, 2, Arc::new(GeminiClient::new(
                    vec![std::env::var("GEMINI_API_KEYS").unwrap().split(',').next().unwrap().to_string()],
                    "gemini-1.5-flash".to_string(),
                    pm.clone()
                )?));
            }
        }

        if let Ok(key) = std::env::var("ANTHROPIC_API_KEY") {
            router.add_provider(RouteLevel::Premium, LlmProviderKind::Anthropic, 1, Arc::new(AnthropicClient::new(
                key,
                "claude-3-5-sonnet-20240620".to_string(),
                pm.clone()
            )?));
        }

        if let Ok(key) = std::env::var("KIMI_API_KEY") {
            router.add_provider(RouteLevel::Premium, LlmProviderKind::Kimi, 1, Arc::new(KimiClient::new(
                key,
                std::env::var("KIMI_MODEL").unwrap_or_else(|_| "kimi-for-coding".to_string()),
                pm.clone()
            )?));
        }

        if let Ok(enabled) = std::env::var("CLAUDE_CODE_ENABLED") {
            if enabled == "true" {
                router.add_provider(RouteLevel::Premium, LlmProviderKind::ClaudeCode, 2, Arc::new(ClaudeCodeClient::new(
                    pm.clone()
                )?));
            }
        }

        // Tier 2: Premium Failover (Antigravity Bridge)
        if let (Ok(key), Ok(endpoint)) = (std::env::var("ANTIGRAVITY_API_KEY"), std::env::var("ANTIGRAVITY_ENDPOINT")) {
            router.add_provider(RouteLevel::Premium, LlmProviderKind::Antigravity, 5, Arc::new(AntigravityClient::new(
                key,
                "antigravity-v1".to_string(),
                endpoint,
                pm.clone()
            )?));
        }

        // V15: SkillManager Initialization (Tactical Knowledge Injection)
        let skill_path = std::path::Path::new("../skills");
        if let Ok(sm) = crate::core::skills::SkillManager::load_from_dir(skill_path) {
            router = router.with_skills(Arc::new(sm));
        }

        Ok(Arc::new(router))
    }
}
