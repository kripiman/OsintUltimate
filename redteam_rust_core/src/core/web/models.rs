use serde::{Deserialize, Serialize};
use ed25519_dalek::VerifyingKey;

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
