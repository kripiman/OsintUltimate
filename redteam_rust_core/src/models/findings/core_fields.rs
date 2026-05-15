use serde::{Deserialize, Serialize};
use super::classification::{Category, Severity};
use super::evidence::ValidationMetadata;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoreFinding {
    pub id: String,
    pub category: Category,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub timestamps: chrono::DateTime<chrono::Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tactical_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    #[serde(default)]
    pub version: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default)]
    pub source_plugin: Option<String>,
    #[serde(default)]
    pub scope_id: String,
    #[serde(default)]
    pub reactive_depth: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attack_path: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExecutionContext {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tactical_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub objective_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub agent: String,
    #[serde(default)]
    pub iteration: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detected: Option<bool>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detection_notes: String,
    #[serde(default)]
    pub validation: ValidationMetadata,
}
