use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ValidationStatus {
    #[default]
    Unverified,
    Verified,
    Suspicious,
    PseudoFalse,
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ValidationMetadata {
    pub status: ValidationStatus,
    pub confidence_score: f32, // 0.0 - 1.0
    pub judge_notes: String,
    pub negative_control_passed: bool,
    pub proof_of_execution: Option<String>,
    pub validated_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceFile {
    pub evidence_type: String,  // screenshot, http-request, terminal-log, scan-output
    pub path: String,           // path relativo al workspace
    pub description: String,
    pub sha256: String,         // chain-of-custody
    pub collected_at: chrono::DateTime<chrono::Utc>,
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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FindingEvidence {
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub primary: Option<Evidence>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<EvidenceFile>,
}
