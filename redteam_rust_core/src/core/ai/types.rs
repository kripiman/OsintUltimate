use serde::{Deserialize, Serialize};
use std::sync::Arc;
use crate::core::ai::traits::LlmClient;
use std::sync::atomic::AtomicU64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RouteLevel {
    Local = 0,   // Ollama / Qwen
    Mid = 1,     // Gemini Flash / GPT-4o-mini
    Premium = 2, // Gemini Pro / GPT-4o / Claude 3.5
}

/// V14 Posture: Represents the operational state of the engagement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Posture {
    /// Passive reconnaissance, ultra-low noise, full proxy isolation.
    #[default]
    Ghost,
    /// Active vulnerability validation, high-precision scanning.
    Strike,
    /// Post-exploitation, C2 session maintenance, and lateral expansion.
    Breach,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LlmProviderKind {
    Local,
    Gemini,
    Anthropic,
    OpenAI,
    AzureOpenAI,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CapabilityGap {
    pub covered_capabilities: std::collections::HashSet<crate::plugins::Capability>,
    pub recommended_capabilities: Vec<crate::plugins::Capability>,
}

pub struct ProviderEntry {
    pub kind: LlmProviderKind,
    pub priority: u8, // 0 is highest
    pub client: Arc<dyn LlmClient>,
}

/// ARCH-11: AdaptiveContext tracks the history of attempts to allow the AI
/// to "learn" from failures (e.g., WAF blocks) within a single target scan.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AdaptiveContext {
    pub previous_actions: Vec<String>,
    pub block_count: u32,
    pub last_status_code: Option<u16>,
    pub was_detected: bool,
    /// WAF evasion stage tracker (0=header, 1=tls, 2=ai, 3=ip, 4=exhausted)
    pub evasion_stage: u8,
    /// URL that triggered the last WAF block
    pub last_blocked_url: Option<String>,
    /// V14 Posture state management
    pub posture: Posture,
}

#[derive(Default)]
pub struct CacheMetrics {
    pub hits: AtomicU64,
    pub misses: AtomicU64,
}
