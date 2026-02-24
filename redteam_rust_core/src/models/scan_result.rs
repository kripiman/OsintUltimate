use super::findings::Finding;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanMetadata {
    pub tool: String,
    pub version: String,
    pub timestamp: DateTime<Utc>,
    pub command_line: String,
}

impl ScanMetadata {
    pub fn new(command_line: &str) -> Self {
        Self {
            tool: "RedTeam-Rust-Engine".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            timestamp: Utc::now(),
            command_line: command_line.to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TargetStatus {
    Pending,
    Scanning,
    Scanned,
    Dead,
    Error,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TargetHost {
    pub host: String,
    pub ip: Option<String>,
    pub status: TargetStatus,
    pub findings: Vec<Finding>,
}


