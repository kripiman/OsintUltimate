use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    ExposedAsset,
    Vulnerability,
    Misconfiguration,
    CredentialLeak,
    TechnologyStack,
    NetworkPort,
    Recon,
    Scanning,
    Availability,
    SCA,
    Compliance,
    Windows,
    Linux,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    #[serde(flatten)]
    pub data: serde_json::Value,
    #[serde(default = "default_confidence")]
    pub confidence: f32,
    #[serde(default)]
    pub verified: bool,
}

fn default_confidence() -> f32 { 0.5 }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PocStrategy {
    /// Restricted command execution without 'sh -c'. 
    SafeCommand,
    /// HTTP(S) request and pattern match. 
    HttpPayload,
    /// TCP connection check.
    TcpCheck,
    /// ICMP echo request.
    IcmpPing,
    /// Integration with Nuclei engine.
    NucleiTemplate,
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
    pub remediation: String,
    pub model: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub poc: Option<PocDefinition>,
    #[serde(default)]
    pub usage: TokenUsage,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub category: Category,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub evidence: Evidence,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ai_analysis: Option<AIAnalysis>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mitre_attack: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub mitre_tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cvss_score: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blackarch_category: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub references: Vec<String>,
    pub timestamps: chrono::DateTime<chrono::Utc>,
}

impl Finding {
    pub fn new(
        id: &str,
        category: Category,
        severity: Severity,
        description: &str,
        evidence: serde_json::Value,
    ) -> Self {
        Self {
            id: id.to_string(),
            category,
            severity: severity.clone(),
            title: description.to_string(), // Default title to description
            description: description.to_string(),
            evidence: Evidence { 
                data: evidence,
                confidence: 0.5,
                verified: false,
            },
            remediation: None,
            parent_id: None,
            ai_analysis: None,
            mitre_attack: None,
            mitre_tags: Vec::new(),
            cvss_score: Some(crate::utils::cvss::Cvss40::calculate(&severity, 0.5)),
            blackarch_category: None,
            references: Vec::new(),
            timestamps: chrono::Utc::now(),
        }
    }

    pub fn with_remediation(mut self, remediation: &str) -> Self {
        self.remediation = Some(remediation.to_string());
        self
    }

    pub fn with_parent(mut self, parent_id: &str) -> Self {
        self.parent_id = Some(parent_id.to_string());
        self
    }

    pub fn with_ai_analysis(mut self, analysis: AIAnalysis) -> Self {
        self.ai_analysis = Some(analysis);
        self
    }

    pub fn with_mitre_attack(mut self, tags: Vec<String>) -> Self {
        self.mitre_attack = Some(tags);
        self
    }

    pub fn with_cvss(mut self, score: f32) -> Self {
        self.cvss_score = Some(score);
        self
    }

    pub fn with_references(mut self, refs: Vec<String>) -> Self {
        self.references = refs;
        self
    }

    pub fn with_blackarch_category(mut self, category: &str) -> Self {
        self.blackarch_category = Some(category.to_string());
        self
    }
}
