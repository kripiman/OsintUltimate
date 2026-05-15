use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_char(&self) -> char {
        match self {
            Severity::Info => 'I',
            Severity::Low => 'L',
            Severity::Medium => 'M',
            Severity::High => 'H',
            Severity::Critical => 'C',
        }
    }
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
    Exploitation,
    TechnologyStack,
    NetworkPort,
    Recon,
    Scanning,
    Availability,
    SCA,
    PostureAudit,
    Windows,
    Linux,
    Compliance,
    BusinessLogicFlaw,
    Idor,
    RaceCondition,
    FileUploadVulnerability,
    AttackPath,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConsolidationUrgency {
    Immediate,   // 0-7 days
    ShortTerm,   // 30 days
    LongTerm,    // 90+ days
}
