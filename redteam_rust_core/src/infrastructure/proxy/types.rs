use serde::{Deserialize, Serialize};
use crate::utils::config::ProxyMode;
use std::time::SystemTime;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub proxies: Vec<String>,
    pub insecure: bool,
    pub mode: ProxyMode,
    pub pool_size: u32,
}

#[derive(Debug, Clone)]
pub struct ManagedExit {
    pub last_seen: SystemTime,
    pub local_port: Option<u16>,
    pub user: Option<String>,
    pub pass: Option<String>,
}
