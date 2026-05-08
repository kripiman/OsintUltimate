pub mod assets;
pub mod handlers;
pub mod models;
pub mod state;
pub mod probe;

pub use models::*;
pub use state::*;

use axum::{
    routing::{get, post},
    Router,
};
use tower_http::cors::{AllowOrigin, CorsLayer};
use std::sync::Arc;
use ed25519_dalek::{SigningKey, Signer};
use tracing::{info, error};

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

pub async fn start_dashboard(state: Arc<state::DashboardState>, port: u16) {
    // Start background prober for API keys (Fase 1.5)
    let probe_state = state.clone();
    tokio::spawn(async move {
        probe::start_credential_prober(probe_state).await;
    });

    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::predicate(move |origin, _| {
            let origin_str = origin.to_str().unwrap_or("");
            origin_str == format!("http://127.0.0.1:{}", port) || 
            origin_str == format!("http://localhost:{}", port) ||
            origin_str == "https://mimikri.me" ||
            origin_str == "http://mimikri.me"
        }))
        .allow_methods([axum::http::Method::GET, axum::http::Method::POST])
        .allow_headers([axum::http::header::AUTHORIZATION, axum::http::header::CONTENT_TYPE]);

    // Rate limiting disabled temporarily due to tower-governor compatibility issues.

    let app = Router::new()
        .route("/", get(assets::serve_index))
        .route("/index.html", get(assets::serve_index))
        .route("/login", get(assets::serve_login))
        .route("/:path", get(assets::serve_asset))
        .route("/api/v1/targets", get(handlers::get_targets))
        .route("/api/v1/targets/:host/findings", get(handlers::get_target_findings))
        .route("/api/v1/stats", get(handlers::get_stats_handler))
        .route("/api/v1/metrics", get(handlers::get_metrics))
        .route("/api/v1/roi/rankings", get(handlers::get_roi_rankings))
        .route("/api/v1/credentials", get(handlers::get_credentials))
        .route("/api/v1/swarm/status", get(handlers::get_swarm_status))
        .route("/api/v1/attack-graph", get(handlers::get_attack_graph))
        .route("/api/v1/containers", get(handlers::get_containers))
        .route("/api/v1/findings/stream", get(handlers::findings_stream))
        .route("/api/v1/approvals", get(handlers::get_approvals))
        .route("/api/v1/approvals/:id/decision", post(handlers::post_approval_decision))
        .route("/api/v2/missions", post(handlers::submit_mission))
        .route("/api/v2/scans/mobile", post(handlers::submit_mobile_scan))
        .route("/api/v2/export", post(handlers::export_report))
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
