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

#[derive(Debug, Serialize, Deserialize)]
pub struct TargetHost {
    pub host: String,
    pub ip: Option<String>,
    pub status: String, // "alive", "dead", "unknown"
    pub findings: Vec<Finding>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanResult {
    pub metadata: ScanMetadata,
    pub targets: Vec<TargetHost>,
}

impl ScanResult {
    pub fn new(command_line: &str) -> Self {
        Self {
            metadata: ScanMetadata {
                tool: "RedTeam-Rust-Engine".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                timestamp: Utc::now(),
                command_line: command_line.to_string(),
            },
            targets: Vec::new(),
        }
    }
}
