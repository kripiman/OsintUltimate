use axum::{
    extract::{State, FromRequestParts},
    response::sse::{Event, KeepAlive, Sse},
    routing::{get, post},
    Router,
    Json,
};
use axum::response::IntoResponse;
use futures::stream::{self, Stream};
use rust_embed::RustEmbed;
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::sync::Arc;
use tokio::sync::broadcast;
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::async_trait;
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use tower_http::cors::AllowOrigin;
use tower_http::cors::CorsLayer;
use tracing::{info, error, warn};

use crate::models::{TargetHost, Finding};

// ─────────────────────────────────────────────────────────────────────────────
// EMBEDDED ASSETS
// ─────────────────────────────────────────────────────────────────────────────

#[derive(RustEmbed)]
#[folder = "src/core/web/assets/"]
struct Assets;

// ─────────────────────────────────────────────────────────────────────────────
// WEB DASHBOARD STATE
// ─────────────────────────────────────────────────────────────────────────────

pub struct DashboardAuth {
    pub verifying_key: VerifyingKey,
    pub session_id: [u8; 16],
}

pub struct DashboardState {
    pub targets: Arc<dashmap::DashMap<String, TargetHost>>,
    pub findings_tx: broadcast::Sender<Finding>,
    pub ram_limit_mb: u64,
    pub approval_gate: Option<Arc<crate::core::approval_gate::ApprovalGate>>,
    pub budget: Option<Arc<crate::core::swarm::TokenBudget>>,
    pub auth: Arc<DashboardAuth>,
}

pub struct ValidatedOperator(pub crate::core::approval_gate::User);

#[async_trait]
impl FromRequestParts<Arc<DashboardState>> for ValidatedOperator {
    type Rejection = (StatusCode, String);

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<DashboardState>,
    ) -> Result<Self, (StatusCode, String)> {
        let auth_header = parts.headers.get("Authorization")
            .and_then(|h| h.to_str().ok())
            .ok_or((StatusCode::UNAUTHORIZED, "Missing Authorization header".to_string()))?;

        if !auth_header.starts_with("Bearer ") {
            return Err((StatusCode::UNAUTHORIZED, "Invalid Authorization header format".to_string()));
        }

        let token_hex = &auth_header[7..];
        let token_bytes = hex::decode(token_hex)
            .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid token encoding".to_string()))?;

        if token_bytes.len() != 96 { // 32B payload + 64B signature
            return Err((StatusCode::UNAUTHORIZED, "Invalid token length".to_string()));
        }

        let (payload, signature_bytes) = token_bytes.split_at(32);
        let signature = Signature::from_slice(signature_bytes)
            .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid signature format".to_string()))?;

        // 1. Verify cryptographic signature
        state.auth.verifying_key.verify(payload, &signature)
            .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid cryptographic signature".to_string()))?;

        // 2. Decode and verify payload: session_id(16B) || created_at(8B) || expiry(8B)
        let session_id = &payload[0..16];
        if session_id != state.auth.session_id {
            return Err((StatusCode::UNAUTHORIZED, "Token session mismatch (expired/invalid session)".to_string()));
        }

        let expiry_bytes = &payload[24..32];
        let expiry = u64::from_be_bytes(expiry_bytes.try_into().unwrap());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap().as_secs();

        if now > expiry {
            return Err((StatusCode::UNAUTHORIZED, "Token has expired".to_string()));
        }

        Ok(ValidatedOperator(crate::core::approval_gate::User {
            id: "dashboard-operator".to_string(),
            name: "Authorized Operator".to_string(),
            role: crate::core::approval_gate::UserRole::Administrator,
            authorized_at: chrono::Utc::now(),
        }))
    }
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

// ─────────────────────────────────────────────────────────────────────────────
// HANDLERS
// ─────────────────────────────────────────────────────────────────────────────

async fn get_targets(
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

async fn serve_asset(path: axum::extract::Path<String>) -> impl IntoResponse {
    let path = path.0;
    let asset = Assets::get(&path).or_else(|| Assets::get("index.html"));

    match asset {
        Some(content) => {
            let mime = mime_guess::from_path(&path).first_or_octet_stream();
            (
                [("Content-Type", mime.as_ref())],
                content.data.to_vec(),
            ).into_response()
        }
        None => (axum::http::StatusCode::NOT_FOUND, "Not Found").into_response(),
    }
}

async fn serve_index() -> impl IntoResponse {
    serve_asset(axum::extract::Path("index.html".to_string())).await
}

async fn findings_stream(
    _auth: ValidatedOperator,
    State(state): State<Arc<DashboardState>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let mut rx = state.findings_tx.subscribe();

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

fn get_current_stats(state: &DashboardState) -> DashboardStats {
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

async fn get_stats_handler(
    _auth: ValidatedOperator,
    State(state): State<Arc<DashboardState>>
) -> Json<DashboardStats> {
    Json(get_current_stats(&state))
}

async fn get_swarm_status(
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

async fn get_attack_graph(
    _auth: ValidatedOperator,
    State(state): State<Arc<DashboardState>>
) -> Json<serde_json::Value> {
    // Generate graph from targets and findings
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

async fn get_containers(_auth: ValidatedOperator) -> Json<Vec<serde_json::Value>> {
    // Mock container status for SandboxDispatcher
    Json(vec![
        serde_json::json!({"id": "osint-sandbox-1", "image": "distroless-python", "status": "running", "cpu": "2%", "memory": "45MB"}),
        serde_json::json!({"id": "osint-sandbox-2", "image": "blackarch-minimal", "status": "idle", "cpu": "0%", "memory": "12MB"}),
    ])
}

async fn get_approvals(
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

#[derive(Deserialize)]
struct ApprovalDecisionPayload {
    decision: String, // "approve" or "reject"
    reason: String,
}

async fn post_approval_decision(
    ValidatedOperator(user): ValidatedOperator,
    State(state): State<Arc<DashboardState>>,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(payload): Json<ApprovalDecisionPayload>,
) -> impl IntoResponse {
    if let Some(gate) = &state.approval_gate {
        if payload.decision == "approve" {
            let _ = gate.approve(&id, &user, &payload.reason).await;
        } else {
            let _ = gate.reject(&id, &user, &payload.reason).await;
        }
        (StatusCode::OK, "Decision recorded").into_response()
    } else {
        (StatusCode::BAD_REQUEST, "Approval gate not configured").into_response()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SERVER LIFECYCLE
// ─────────────────────────────────────────────────────────────────────────────

pub fn generate_dashboard_token(
    signing_key: &SigningKey,
    session_id: [u8; 16],
    expiry_secs: u64,
) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap().as_secs();
    
    let mut payload = [0u8; 32];
    payload[0..16].copy_from_slice(&session_id);
    payload[16..24].copy_from_slice(&now.to_be_bytes());
    payload[24..32].copy_from_slice(&(now + expiry_secs).to_be_bytes());

    let signature = signing_key.sign(&payload);
    let mut combined = Vec::with_capacity(96);
    combined.extend_from_slice(&payload);
    combined.extend_from_slice(&signature.to_bytes());
    
    hex::encode(combined)
}

pub async fn start_dashboard(state: Arc<DashboardState>, port: u16) {
    // RESTRICTED CORS
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::predicate(move |origin, _| {
            let origin_str = origin.to_str().unwrap_or("");
            origin_str.starts_with("http://127.0.0.1") || origin_str.starts_with("http://localhost")
        }))
        .allow_methods([axum::http::Method::GET, axum::http::Method::POST])
        .allow_headers([axum::http::header::AUTHORIZATION, axum::http::header::CONTENT_TYPE]);

    let app = Router::new()
        .route("/", get(serve_index))
        .route("/index.html", get(serve_index))
        .route("/:path", get(serve_asset))
        .route("/api/v1/targets", get(get_targets))
        .route("/api/v1/stats", get(get_stats_handler))
        .route("/api/v1/swarm/status", get(get_swarm_status))
        .route("/api/v1/attack-graph", get(get_attack_graph))
        .route("/api/v1/containers", get(get_containers))
        .route("/api/v1/findings/stream", get(findings_stream))
        .route("/api/v1/approvals", get(get_approvals))
        .route("/api/v1/approvals/:id/decision", post(post_approval_decision))
        .layer(cors)
        .with_state(state);

    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    info!("🚀 DASHBOARD: Starting on http://{}", addr);

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            error!("❌ DASHBOARD: Failed to bind to {}: {}", addr, e);
            return;
        }
    };

    if let Err(e) = axum::serve(listener, app).await {
        error!("❌ DASHBOARD: Server error: {}", e);
    }
}
