use serde::{Deserialize, Serialize};
use ed25519_dalek::VerifyingKey;
use crate::models::ReportPlatform;

pub struct DashboardAuth {
    pub verifying_key: VerifyingKey,
    pub session_id: [u8; 16],
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DashboardStats {
    pub ram_mb: u64,
    pub ram_limit_mb: u64,
    pub active_threads: usize,
    pub active_proxies: usize,
    pub tokens_used: u32,
    pub token_limit: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SwarmAgentStatus {
    pub role: String,
    pub status: String,
    pub last_action: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SwarmStatusResponse {
    pub agents: Vec<SwarmAgentStatus>,
    pub total_tokens: u32,
    pub max_tokens: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WsEvent {
    pub type_name: String,
    pub payload: serde_json::Value,
    pub stats: DashboardStats,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ExportRequest {
    pub platform: ReportPlatform,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct MissionRequest {
    pub target: Option<String>,
    pub apk: Option<String>,
    pub program_name: String,
    pub in_scope: Vec<String>,
    pub out_of_scope: Vec<String>,
    pub profile: String,
    pub stealth: bool,
    pub vuln_scan: bool,
    pub oob_enabled: bool,
    pub use_swarm: bool,
    pub max_concurrency: u8,
    pub notes: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CredentialStatus {
    pub service: String,
    pub status: String, // "Not Added", "Idle", "Working", "Failed"
    pub last_check: Option<String>,
    pub error: Option<String>,
}
