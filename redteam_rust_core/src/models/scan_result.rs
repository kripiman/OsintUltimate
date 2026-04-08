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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TargetType {
    Network,
    Web,
    Cloud,
    Host,
    Osint,
    Container,
    ActiveDirectory,
    Windows,
    Linux,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TargetHost {
    pub host: String,
    pub ip: Option<String>,
    /// V12 HARDENING: Permanent IP pinning for security tools (DNS Rebinding Mitigation).
    #[serde(default)]
    pub resolved_ip: Option<String>,
    pub status: TargetStatus,
    pub target_type: TargetType,
    pub findings: Arc<Vec<Finding>>,
    pub tool_suggestions: Arc<Vec<String>>,
    #[serde(default = "default_arc_json")]
    pub tactical_context: Arc<serde_json::Value>,
    #[serde(default = "default_arc_json")]
    pub extra_data: Arc<serde_json::Value>,
}

impl TargetHost {
    /// V12: Returns the most secure address for network operations (Priority: pinned IP).
    /// V13: Hardened to force use of resolved_ip for ALL critical operations.
    /// FALLBACK WARNING: Using this method may fallback to a hostname, which is unsafe against DNS Rebinding.
    pub fn target_addr(&self) -> &str {
        match &self.resolved_ip {
            Some(ip) => ip,
            None => {
                // If not resolved, we fallback to ip but log a warning as it's a security risk (DNS Rebinding)
                // V13 Note: This fallback is deprecated. Use pinned_addr() for all network-bound plugins.
                self.ip.as_deref().unwrap_or(&self.host)
            }
        }
    }

    /// V13: Force retrieval of a pinned IP or error out. 
    /// MANDATORY for all sensitive operations (PoC, Exploits, Scanning) to prevent DNS Rebinding.
    pub fn pinned_addr(&self) -> Result<&str, anyhow::Error> {
        self.resolved_ip.as_deref()
            .ok_or_else(|| {
                anyhow::anyhow!("V13 Security Violation: Operation requires a pinned IP (resolved_ip) to prevent DNS Rebinding. Check Liveness stage.")
            })
    }
}

fn default_arc_json() -> Arc<serde_json::Value> {
    Arc::new(serde_json::json!({}))
}

fn default_arc_vec<T>() -> Arc<Vec<T>> {
    Arc::new(Vec::new())
}


