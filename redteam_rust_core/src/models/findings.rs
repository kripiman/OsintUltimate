use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    ExposedAsset,
    Vulnerability,
    Misconfiguration,
    CredentialLeak,
    TechnologyStack,
    NetworkPort,
    Recon,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    #[serde(flatten)]
    pub data: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub category: Category,
    pub severity: Severity,
    pub description: String,
    pub evidence: Evidence,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
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
            severity,
            description: description.to_string(),
            evidence: Evidence { data: evidence },
            remediation: None,
        }
    }

    pub fn with_remediation(mut self, remediation: &str) -> Self {
        self.remediation = Some(remediation.to_string());
        self
    }
}
