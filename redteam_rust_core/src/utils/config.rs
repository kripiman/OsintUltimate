use std::env;
use anyhow::{Result, anyhow};

pub struct Config {
    pub do_token: Option<String>,
    pub ollama_url: String,
    pub max_tokens: u32,
    pub soft_memory_limit_mb: usize,
    pub hard_memory_limit_mb: usize,
    pub default_concurrency: usize,
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            do_token: env::var("DIGITALOCEAN_TOKEN").ok(),
            ollama_url: env::var("OLLAMA_URL").unwrap_or_else(|_| "http://localhost:11434".to_string()),
            max_tokens: env::var("MAX_TOKENS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(4096),
            soft_memory_limit_mb: env::var("SOFT_MEMORY_LIMIT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(600),
            hard_memory_limit_mb: env::var("HARD_MEMORY_LIMIT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(900),
            default_concurrency: env::var("DEFAULT_CONCURRENCY")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(10),
        }
    }

    pub fn require_do_token(&self) -> Result<String> {
        self.do_token.clone()
            .ok_or_else(|| anyhow!("DIGITALOCEAN_TOKEN environment variable not set"))
    }
}
