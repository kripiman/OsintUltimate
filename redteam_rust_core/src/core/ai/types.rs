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
    Antigravity, // V15: OpenSource/Custom Failover Endpoint
    Kimi,
    ClaudeCode,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CapabilityGap {
    pub covered_capabilities: std::collections::HashSet<crate::plugins::Capability>,
    pub recommended_capabilities: Vec<crate::plugins::Capability>,
}

#[derive(Clone)]
pub struct ProviderEntry {
    pub kind: LlmProviderKind,
    pub priority: u8, // 0 is highest
    pub client: Arc<dyn LlmClient>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
pub enum CavemanLevel {
    /// No caveman optimization.
    Off,
    /// No filler/hedging. Keep articles + full sentences. Professional but tight.
    Lite,
    /// Drop articles, fragments OK, short synonyms. Classic caveman.
    Full,
    /// Maximum compression. Telegraphic. Abbreviate everything.
    Ultra,
    /// Classical Chinese literary compression. ~80-90% character reduction.
    #[default]
    WenyanUltra,
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
    /// V14.1 Token optimization state
    pub current_caveman: CavemanLevel,
}

#[derive(Default)]
pub struct CacheMetrics {
    pub hits: AtomicU64,
    pub misses: AtomicU64,
}

/// V15: PLUGIN RAG OPTIMIZATION
/// Represents a plugin's vector representation for semantic tool selection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginVector {
    pub name: String,
    pub embedding: Vec<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PluginIndex {
    pub vectors: Vec<PluginVector>,
    #[serde(skip)]
    pub last_updated: Option<chrono::DateTime<chrono::Utc>>,
}
