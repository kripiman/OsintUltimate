use std::sync::Arc;
use anyhow::{Result, Context};
use tracing::{info, warn};
use crate::core::ai_cascade::{TieredAIRouter, RouteLevel, LlmProviderKind};
use crate::core::agent::{OllamaClient, GeminiClient, AnthropicClient, OpenAIClient, AzureOpenAIClient};
use crate::utils::{InfrastructureType, HardwareInfo};

pub struct EngineFactory;

impl EngineFactory {
    /// Detect infrastructure and return auto-adjusted concurrency limits
    pub fn detect_infrastructure_limits() -> (HardwareInfo, usize, usize, usize) {
        let hw = crate::utils::detect_infrastructure();
        let mut concurrency = 10;
        let mut soft_limit = 600;
        let mut hard_limit = 900;

        match hw.infra_type {
            InfrastructureType::UltraLowMemory => {
                concurrency = 10;
                soft_limit = 500;
                hard_limit = 850;
            }
            InfrastructureType::LocalPC => {
                concurrency = 30;
                soft_limit = 800;
                hard_limit = 1200;
            }
            InfrastructureType::Hybrid => {
                concurrency = 60;
                soft_limit = 1200;
                hard_limit = 2000;
            }
            InfrastructureType::Server => {
                concurrency = 150;
                soft_limit = 4000;
                hard_limit = 8000;
            }
        }
        (hw, concurrency, soft_limit, hard_limit)
    }

    /// Build a pre-configured AI Router based on available environment variables
    pub fn build_default_router(ollama_url: String) -> Result<Arc<TieredAIRouter>> {
        let mut router = TieredAIRouter::new();
        
        // Tier 0: Local (Ollama)
        router.add_provider(RouteLevel::Local, LlmProviderKind::Local, 0, Arc::new(OllamaClient::new(
            ollama_url,
            "qwen2.5-coder:7b".to_string()
        )?));

        // Tier 1: Mid
        if let (Ok(endpoint), Ok(key)) = (std::env::var("AZURE_OPENAI_ENDPOINT"), std::env::var("AZURE_OPENAI_KEY")) {
            router.add_provider(RouteLevel::Mid, LlmProviderKind::AzureOpenAI, 0, Arc::new(AzureOpenAIClient::new(
                endpoint,
                key,
                "gpt-4o-mini".to_string(),
                "2024-02-01".to_string()
            )?));
        }

        if let Ok(key) = std::env::var("OPENAI_API_KEY") {
            router.add_provider(RouteLevel::Mid, LlmProviderKind::OpenAI, 1, Arc::new(OpenAIClient::new(
                key,
                "gpt-4o-mini".to_string()
            )?));
        }

        // Tier 2: Premium
        if let Ok(keys_str) = std::env::var("GEMINI_API_KEYS") {
            let keys: Vec<String> = keys_str.split(',').map(|k| k.trim().to_string()).filter(|k| !k.is_empty()).collect();
            if !keys.is_empty() {
                router.add_provider(RouteLevel::Premium, LlmProviderKind::Gemini, 0, Arc::new(GeminiClient::new(
                    keys, 
                    "gemini-1.5-pro".to_string()
                )?));
                
                // Also add Flash for Mid-tier if Gemini is available
                router.add_provider(RouteLevel::Mid, LlmProviderKind::Gemini, 2, Arc::new(GeminiClient::new(
                    vec![std::env::var("GEMINI_API_KEYS").unwrap().split(',').next().unwrap().to_string()],
                    "gemini-1.5-flash".to_string()
                )?));
            }
        }

        if let Ok(key) = std::env::var("ANTHROPIC_API_KEY") {
            router.add_provider(RouteLevel::Premium, LlmProviderKind::Anthropic, 1, Arc::new(AnthropicClient::new(
                key,
                "claude-3-5-sonnet-20240620".to_string()
            )?));
        }

        Ok(Arc::new(router))
    }
}
