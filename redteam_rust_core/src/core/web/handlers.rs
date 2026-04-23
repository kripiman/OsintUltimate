use axum::{
    extract::{State, Path},
    response::sse::{Event, KeepAlive, Sse},
    Json,
};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use futures::stream::{self, Stream};
use std::convert::Infallible;
use std::sync::Arc;
use tokio::sync::broadcast;

use super::state::{DashboardState, ValidatedOperator};
use super::models::{DashboardStats, MissionRequest, SwarmAgentStatus, SwarmStatusResponse};

pub async fn get_targets(
    _auth: ValidatedOperator,
    State(state): State<Arc<DashboardState>>
) -> Json<Vec<serde_json::Value>> {
    let targets: Vec<serde_json::Value> = state.targets.iter().map(|kv| {
        let t = kv.value();
        serde_json::json!({
            "host": t.host,
            "ip": t.ip,
            "status": format!("{:?}", t.status),
            "findings_count": t.findings.len(),
            "target_type": format!("{:?}", t.target_type),
        })
    }).collect();
    Json(targets)
}

pub async fn findings_stream(
    _auth: ValidatedOperator,
    State(state): State<Arc<DashboardState>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = state.findings_tx.subscribe();

    let stream = stream::unfold((rx, state), |(mut rx, state)| async move {
        loop {
            match rx.recv().await {
                Ok(finding) => {
                    let stats = get_current_stats(&state);
                    let event = serde_json::json!({
                        "type": "finding",
                        "payload": {
                            "tool": "Engine",
                            "severity": format!("{:?}", finding.severity),
                            "title": finding.title,
                            "category": format!("{:?}", finding.category),
                        },
                        "stats": stats,
                    });
                    
                    if let Ok(data) = serde_json::to_string(&event) {
                        return Some((Ok(Event::default().data(data)), (rx, state)));
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(_) => break,
            }
        }
        None
    });

    Sse::new(stream).keep_alive(KeepAlive::default())
}

pub fn get_current_stats(state: &DashboardState) -> DashboardStats {
    let mut sys = sysinfo::System::new_all();
    sys.refresh_all();
    
    let tokens = state.budget.as_ref().map(|b| b.current_total()).unwrap_or(0);
    let limit = state.budget.as_ref().map(|b| b.max_tokens).unwrap_or(0);

    DashboardStats {
        ram_mb: sys.used_memory() / 1024 / 1024,
        ram_limit_mb: state.ram_limit_mb,
        active_threads: 0, 
        active_proxies: 0,
        tokens_used: tokens,
        token_limit: limit,
    }
}

pub async fn get_stats_handler(
    _auth: ValidatedOperator,
    State(state): State<Arc<DashboardState>>
) -> Json<DashboardStats> {
    Json(get_current_stats(&state))
}

pub async fn get_swarm_status(
    _auth: ValidatedOperator,
    State(state): State<Arc<DashboardState>>
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

pub async fn get_attack_graph(
    _auth: ValidatedOperator,
    State(state): State<Arc<DashboardState>>
) -> Json<serde_json::Value> {
    let mut nodes = Vec::new();
    let mut edges = Vec::new();

    for kv in state.targets.iter() {
        let t = kv.value();
        nodes.push(serde_json::json!({
            "id": t.host,
            "label": t.host,
            "type": "target",
            "severity": "Info"
        }));

        for f in t.findings.iter() {
            nodes.push(serde_json::json!({
                "id": f.id,
                "label": f.title,
                "type": "finding",
                "severity": format!("{:?}", f.severity)
            }));
            edges.push(serde_json::json!({
                "source": t.host,
                "target": f.id
            }));
        }
    }

    Json(serde_json::json!({
        "nodes": nodes,
        "links": edges
    }))
}

pub async fn submit_mission(
    _auth: ValidatedOperator,
    State(state): State<Arc<DashboardState>>,
    Json(req): Json<MissionRequest>,
) -> impl IntoResponse {
    if let Some(tx) = &state.mission_tx {
        match tx.send(req).await {
            Ok(_) => (StatusCode::ACCEPTED, "Mission queued").into_response(),
            Err(_) => (StatusCode::SERVICE_UNAVAILABLE, "Engine not ready").into_response(),
        }
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "Mission channel not configured").into_response()
    }
}

pub async fn get_containers(_auth: ValidatedOperator) -> Json<Vec<serde_json::Value>> {
    Json(vec![
        serde_json::json!({"id": "osint-sandbox-1", "image": "distroless-python", "status": "running", "cpu": "2%", "memory": "45MB"}),
        serde_json::json!({"id": "osint-sandbox-2", "image": "blackarch-minimal", "status": "idle", "cpu": "0%", "memory": "12MB"}),
    ])
}

pub async fn get_approvals(
    _auth: ValidatedOperator,
    State(state): State<Arc<DashboardState>>
) -> Json<Vec<serde_json::Value>> {
    if let Some(gate) = &state.approval_gate {
        let approvals: Vec<serde_json::Value> = gate.pending_approvals.iter().map(|kv| {
            let req = kv.value();
            serde_json::json!({
                "id": req.id,
                "action": req.action,
                "risk_level": req.risk_level,
                "reason": req.reason,
                "requested_by": req.requested_by,
            })
        }).collect();
        Json(approvals)
    } else {
        Json(vec![])
    }
}

#[derive(serde::Deserialize)]
pub struct ApprovalDecisionPayload {
    pub decision: String, 
    pub reason: String,
    pub handover_payload: Option<String>,
}

pub async fn post_approval_decision(
    ValidatedOperator(user): ValidatedOperator,
    State(state): State<Arc<DashboardState>>,
    Path(id): Path<String>,
    Json(payload): Json<ApprovalDecisionPayload>,
) -> impl IntoResponse {
    if let Some(gate) = &state.approval_gate {
        if payload.decision == "approve" {
            let _ = gate.approve(&id, &user, &payload.reason, payload.handover_payload).await;
        } else {
            let _ = gate.reject(&id, &user, &payload.reason).await;
        }
        (StatusCode::OK, "Decision recorded").into_response()
    } else {
        (StatusCode::BAD_REQUEST, "Approval gate not configured").into_response()
    }
}
