use std::env;
use anyhow::{Result, anyhow};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ProxyMode {
    Dante,
    Shadowsocks,
    Hysteria,
}

pub struct Config {
    pub do_token: Option<String>,
    pub do_ssh_key_id: Option<String>,
    pub database_url: String,
    pub ollama_url: String,
    pub max_tokens: u32,
    pub soft_memory_limit_mb: usize,
    pub hard_memory_limit_mb: usize,
    pub default_concurrency: usize,
    pub proxy_mode: ProxyMode,
    pub proxy_pool_size: u32,
    pub chaos_api_key: Option<String>,
    pub netlas_api_key: Option<String>,
    pub securitytrails_api_key: Option<String>,
    pub shodan_api_key: Option<String>,
    pub criminalip_api_key: Option<String>,
    pub netlas_daily_budget: u32,
    pub caido_api_key: Option<String>,
    pub caido_api_url: String,
    pub mcp_token: Option<String>,
    pub discord_webhook_url: Option<String>,
    pub certstream_keywords: Vec<String>,
    pub nuclei_tags: Option<String>,
    pub nuclei_severity: Option<String>,
    pub nuclei_custom_templates: Option<String>,
    pub mobsf_url: Option<String>,
    pub mobsf_api_key: Option<String>,
    pub mobsf_timeout_secs: u64,
    pub cosign_public_key: Option<String>,
    pub cosign_oidc_issuer: Option<String>,
    pub supply_timeout_syft_secs: u64,
    pub supply_timeout_grype_secs: u64,
    pub supply_timeout_cosign_secs: u64,
    pub vigil_url: Option<String>,
    pub vigil_api_key: Option<String>,
    pub rebuff_url: Option<String>,
    pub rebuff_api_token: Option<String>,
    pub policy_file: Option<String>,
    pub strict_scope: bool,
    pub nuclei_auto_update: bool,
    pub h1_username: Option<String>,
    pub h1_api_key: Option<String>,
    pub bugcrowd_api_key: Option<String>,
    pub intigriti_token: Option<String>,
    pub bb_program_handle: Option<String>,
    pub openai_api_key: Option<String>,
    pub anthropic_api_key: Option<String>,
    pub gemini_api_keys: Option<String>,
    pub kimi_api_key: Option<String>,
    pub claude_code_enabled: bool,
    pub antigravity_api_key: Option<String>,
    pub antigravity_endpoint: Option<String>,
    pub azure_openai_key: Option<String>,
    pub azure_openai_endpoint: Option<String>,
    pub clairvoyance_wordlist_path: Option<String>,
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            do_token: env::var("DIGITALOCEAN_TOKEN").ok(),
            do_ssh_key_id: env::var("DO_SSH_KEY_ID").ok(),
            database_url: env::var("DATABASE_URL").unwrap_or_else(|_| "postgres://osintuser:WENYANULTRA_SECURE_PASS@localhost:5432/osintdb".to_string()),
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
            proxy_mode: env::var("PROXY_MODE")
                .ok()
                .map(|s| match s.to_lowercase().as_str() {
                    "shadowsocks" => ProxyMode::Shadowsocks,
                    "hysteria" => ProxyMode::Hysteria,
                    _ => ProxyMode::Dante,
                })
                .unwrap_or(ProxyMode::Dante),
            proxy_pool_size: env::var("PROXY_POOL_SIZE")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0),
            chaos_api_key: env::var("CHAOS_API_KEY").ok(),
            netlas_api_key: env::var("NETLAS_API_KEY").ok(),
            securitytrails_api_key: env::var("SECURITYTRAILS_API_KEY").ok(),
            shodan_api_key: env::var("SHODAN_API_KEY").ok(),
            criminalip_api_key: env::var("CRIMINALIP_API_KEY").ok(),
            netlas_daily_budget: env::var("NETLAS_DAILY_BUDGET")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(33), // Default ~1000/month
            caido_api_key: env::var("CAIDO_API_KEY").ok(),
            caido_api_url: env::var("CAIDO_API_URL").unwrap_or_else(|_| "http://localhost:8080/graphql".to_string()),
            mcp_token: env::var("MCP_TOKEN").ok(),
            discord_webhook_url: env::var("DISCORD_WEBHOOK_URL").ok(),
            certstream_keywords: env::var("CERTSTREAM_KEYWORDS")
                .unwrap_or_default()
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_lowercase)
                .collect(),
            nuclei_tags: env::var("NUCLEI_TAGS").ok(),
            nuclei_severity: env::var("NUCLEI_SEVERITY").ok(),
            nuclei_custom_templates: env::var("NUCLEI_CUSTOM_TEMPLATES").ok(),
            mobsf_url: env::var("MOBSF_URL").ok(),
            mobsf_api_key: env::var("MOBSF_API_KEY").ok(),
            mobsf_timeout_secs: env::var("MOBSF_TIMEOUT_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(1200),
            cosign_public_key: env::var("COSIGN_PUBLIC_KEY_PATH").ok(),
            cosign_oidc_issuer: env::var("COSIGN_OIDC_ISSUER").ok(),
            supply_timeout_syft_secs: env::var("SUPPLY_TIMEOUT_SYFT_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(300),
            supply_timeout_grype_secs: env::var("SUPPLY_TIMEOUT_GRYPE_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(600),
            supply_timeout_cosign_secs: env::var("SUPPLY_TIMEOUT_COSIGN_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(120),
            vigil_url: env::var("VIGIL_URL").ok(),
            vigil_api_key: env::var("VIGIL_API_KEY").ok(),
            rebuff_url: env::var("REBUFF_URL").ok(),
            rebuff_api_token: env::var("REBUFF_API_TOKEN").ok(),
            policy_file: env::var("POLICY_FILE").ok(),
            strict_scope: env::var("STRICT_SCOPE").ok().and_then(|s| s.parse().ok()).unwrap_or(false),
            nuclei_auto_update: env::var("NUCLEI_AUTO_UPDATE").ok().and_then(|s| s.parse().ok()).unwrap_or(false),
            h1_username: env::var("H1_USERNAME").ok(),
            h1_api_key: env::var("H1_API_KEY").ok(),
            bugcrowd_api_key: env::var("BUGCROWD_API_KEY").ok(),
            intigriti_token: env::var("INTIGRITI_TOKEN").ok(),
            bb_program_handle: env::var("BB_PROGRAM_HANDLE").ok(),
            openai_api_key: env::var("OPENAI_API_KEY").ok(),
            anthropic_api_key: env::var("ANTHROPIC_API_KEY").ok(),
            gemini_api_keys: env::var("GEMINI_API_KEYS").ok(),
            kimi_api_key: env::var("KIMI_API_KEY").ok(),
            claude_code_enabled: env::var("CLAUDE_CODE_ENABLED").ok().and_then(|s| s.parse().ok()).unwrap_or(false),
            antigravity_api_key: env::var("ANTIGRAVITY_API_KEY").ok(),
            antigravity_endpoint: env::var("ANTIGRAVITY_ENDPOINT").ok(),
            azure_openai_key: env::var("AZURE_OPENAI_KEY").ok(),
            azure_openai_endpoint: env::var("AZURE_OPENAI_ENDPOINT").ok(),
            clairvoyance_wordlist_path: env::var("CLAIRVOYANCE_WORDLIST").ok(),
        }
    }

    pub fn require_do_token(&self) -> Result<String> {
        self.do_token.clone()
            .ok_or_else(|| anyhow!("DIGITALOCEAN_TOKEN environment variable not set"))
    }
}
