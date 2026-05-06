use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StealthPolicy {
    pub ja3_spoofing: bool,
    pub http2_priority_manipulation: bool,
    pub header_order_randomization: bool,
    pub user_agent_rotation: bool,
}

impl Default for StealthPolicy {
    fn default() -> Self {
        Self {
            ja3_spoofing: true,
            http2_priority_manipulation: true,
            header_order_randomization: true,
            user_agent_rotation: true,
        }
    }
}
