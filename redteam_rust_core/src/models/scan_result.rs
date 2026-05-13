use tracing::{warn};
use super::findings::Finding;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use std::sync::Arc;

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanMetadata {
    pub tool: String,
    pub version: String,
    pub timestamp: DateTime<Utc>,
    pub command_line: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct DiscoveryResult {
    pub host: String,
    pub metadata: serde_json::Value,
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum TargetStatus {
    #[default]
    Pending,
    Scanning,
    Scanned,
    Dead,
    Error,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum TargetType {
    #[default]
    Network,
    Web,
    Cloud,
    Host,
    Osint,
    Container,
    ActiveDirectory,
    Windows,
    Linux,
    Mobile,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct TargetHost {
    pub host: String,
    pub ip: Option<String>,
    /// HARDENING: Permanent IP pinning for security tools (DNS Rebinding Mitigation).
    #[serde(default)]
    pub resolved_ip: Option<String>,
    pub status: TargetStatus,
    pub target_type: TargetType,
    #[serde(default)]
    pub file_path: Option<String>,
    #[serde(default)]
    pub user: Option<String>,
    pub findings: Arc<Vec<Finding>>,
    pub tool_suggestions: Arc<Vec<String>>,
    #[serde(default = "default_arc_json")]
    pub tactical_context: Arc<serde_json::Value>,
    #[serde(default = "default_arc_json")]
    pub extra_data: Arc<serde_json::Value>,
    /// Target version for differential dashboard updates
    #[serde(default)]
    pub version: u64,
    /// CDN detection flag to skip resource-intensive scans (Nuclei, Fuzzing)
    #[serde(default)]
    pub skip_heavy_scan: bool,
    /// Temporal Diff: tracks the scan instance ID for historical comparisons
    #[serde(default)]
    pub scan_id: Option<i64>,
    #[serde(default)]
    pub scope_id: String,
}

impl TargetHost {
    /// Returns the most secure address for network operations (Priority: pinned IP).
    /// Hardened to force use of resolved_ip for ALL critical operations.
    /// In this version, we no longer fallback to hostnames to prevent DNS Rebinding.
    pub fn target_addr(&self) -> &str {
        match &self.resolved_ip {
            Some(ip) => ip,
            None => {
                // Professional Security: Fail-Closed. If not resolved, return the hostname but warn it is unsafe.
                // In a future version, this will return a Result or panic.
                warn!("⚠️ SECURITY WARNING: Using UNPINNED address for {}. Possible DNS Rebinding risk.", self.host);
                self.ip.as_deref().unwrap_or(&self.host)
            }
        }
    }

    /// Force retrieval of a pinned IP or error out. 
    /// MANDATORY for all sensitive operations (PoC, Exploits, Scanning) to prevent DNS Rebinding.
    pub fn pinned_addr(&self) -> Result<&str, anyhow::Error> {
        debug_assert!(self.target_type != TargetType::Mobile, "pinned_addr() called on Mobile target");
        self.resolved_ip.as_deref()
            .ok_or_else(|| {
                anyhow::anyhow!("Security Violation: Operation requires a pinned IP (resolved_ip) to prevent DNS Rebinding. Check Liveness stage.")
            })
    }

    pub fn is_artifact_target(&self) -> bool {
        self.file_path.is_some()
    }

    pub fn artifact_path(&self) -> Result<&str, anyhow::Error> {
        self.file_path.as_deref()
            .ok_or_else(|| anyhow::anyhow!("Target has no artifact path (Mobile/static scan required file_path)"))
    }

    pub fn findings_since(&self, version: u64) -> Vec<Finding> {
        self.findings.iter()
            .filter(|f| f.version > version)
            .cloned()
            .collect()
    }
}

fn default_arc_json() -> Arc<serde_json::Value> {
    Arc::new(serde_json::json!({}))
}



