/// handlers/status.rs — Items 7, 11 from PLAN v3 6.B mapping table.
/// pub async fn get_swarm_status  (L128–L147)
/// pub async fn get_containers    (L252–L257)
use axum::{
    extract::State,
    Json,
};
use std::sync::Arc;

use super::super::state::{DashboardState, ValidatedOperator};
use super::super::models::{SwarmAgentStatus, SwarmStatusResponse};

pub async fn get_swarm_status(
    _auth: ValidatedOperator,
    State(state): State<Arc<DashboardState>>,
) -> Json<SwarmStatusResponse> {
    let tokens = state.budget.as_ref().map(|b| b.current_total()).unwrap_or(0);
    let limit = state.budget.as_ref().map(|b| b.max_tokens).unwrap_or(0);

    let agents = vec![
        SwarmAgentStatus { role: "Planner".to_string(), status: "Waiting".to_string(), last_action: "Initial analysis".to_string() },
        SwarmAgentStatus { role: "Scout".to_string(), status: "Idle".to_string(), last_action: "Port scan".to_string() },
        SwarmAgentStatus { role: "Exploiter".to_string(), status: "Idle".to_string(), last_action: "Vulnerability check".to_string() },
        SwarmAgentStatus { role: "Reporter".to_string(), status: "Idle".to_string(), last_action: "Drafting report".to_string() },
    ];

    Json(SwarmStatusResponse {
        agents,
        total_tokens: tokens,
        max_tokens: limit,
    })
}

pub async fn get_containers(_auth: ValidatedOperator) -> Json<Vec<serde_json::Value>> {
    Json(vec![
        serde_json::json!({"id": "osint-sandbox-1", "image": "distroless-python", "status": "running", "cpu": "2%", "memory": "45MB"}),
        serde_json::json!({"id": "osint-sandbox-2", "image": "blackarch-minimal", "status": "idle", "cpu": "0%", "memory": "12MB"}),
    ])
}
