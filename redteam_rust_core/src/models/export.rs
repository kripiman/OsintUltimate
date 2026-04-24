use serde::{Deserialize, Serialize};
use super::Severity;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ReportPlatform {
    #[serde(rename = "h1")]
    HackerOne,
    #[serde(rename = "bugcrowd")]
    BugCrowd,
    #[serde(rename = "intigriti")]
    Intigriti,
}

impl ReportPlatform {
    pub fn display_name(&self) -> &str {
        match self {
            Self::HackerOne => "HackerOne",
            Self::BugCrowd => "Bugcrowd",
            Self::Intigriti => "Intigriti",
        }
    }

    pub fn severity_label(&self, severity: &Severity) -> &str {
        match (self, severity) {
            (Self::HackerOne, Severity::Critical) => "critical",
            (Self::HackerOne, Severity::High) => "high",
            (Self::HackerOne, Severity::Medium) => "medium",
            (Self::HackerOne, Severity::Low) => "low",
            (Self::HackerOne, Severity::Info) => "informational",
            (Self::BugCrowd, Severity::Critical) => "P1",
            (Self::BugCrowd, Severity::High) => "P2",
            (Self::BugCrowd, Severity::Medium) => "P3",
            (Self::BugCrowd, Severity::Low) => "P4",
            (Self::BugCrowd, Severity::Info) => "P5",
            (Self::Intigriti, Severity::Critical) => "Critical",
            (Self::Intigriti, Severity::High) => "High",
            (Self::Intigriti, Severity::Medium) => "Medium",
            (Self::Intigriti, Severity::Low) => "Low",
            (Self::Intigriti, Severity::Info) => "Informational",
        }
    }

    pub fn filename(&self) -> &str {
        match self {
            Self::HackerOne => "report_h1.md",
            Self::BugCrowd => "report_bugcrowd.md",
            Self::Intigriti => "report_intigriti.md",
        }
    }
}
