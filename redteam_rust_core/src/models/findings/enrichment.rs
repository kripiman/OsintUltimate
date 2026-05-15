use serde::{Deserialize, Serialize};
use super::classification::ConsolidationUrgency;

#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PocStrategy {
    SafeCommand,
    HttpPayload,
    TcpCheck,
    IcmpPing,
    NucleiTemplate,
    HumanVerified,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ValidatedPoc {
    Nmap { 
        port: u16, 
        flags: Vec<String> 
    },
    Curl { 
        path: String, 
        headers: Vec<(String, String)> 
    },
    Ping,
    Dig,
    TcpConnect { 
        port: u16 
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PocDefinition {
    pub strategy: PocStrategy,
    pub payload: String,
    pub expected_pattern: String,
    #[serde(default)]
    pub is_intrusive: bool,
    #[serde(default)]
    pub complexity_score: u8, // 0-100 rating
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TokenUsage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIAnalysis {
    pub summary: String,
    pub impact: String,
    pub stealth_notes: String,
    pub risk_score: u8,
    pub confidence: f32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mitre_attack: Option<Vec<String>>,
    pub exploit_path: String,
    pub model: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub poc: Option<PocDefinition>,
    #[serde(default)]
    pub usage: TokenUsage,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FindingEnrichment {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ai_analysis: Option<AIAnalysis>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mitre_attack: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mitre_tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cvss_score: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cvss_vector: Option<String>,
    #[serde(default)]
    pub cvss_version: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cwe: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blackarch_category: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consolidation_urgency: Option<ConsolidationUrgency>,
    #[serde(default)]
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub is_new: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub similarity_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub merged_from: Vec<String>,
}
