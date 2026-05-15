use serde::{Deserialize, Serialize};
use crate::models::Finding;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpilledEvent {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub severity: String,
    pub finding_id: String,
    #[serde(flatten)]
    pub finding: Finding,
}

impl SpilledEvent {
    pub fn from_finding(finding: Finding) -> Self {
        Self {
            timestamp: chrono::Utc::now(),
            severity: format!("{:?}", finding.core.severity),
            finding_id: finding.core.id.clone(),
            finding,
        }
    }
}
