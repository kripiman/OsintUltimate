use axum::{
    extract::State,
    response::sse::{Event, KeepAlive, Sse},
    routing::{get, post},
    Router,
    Json,
};
use axum::response::IntoResponse;
use futures_util::stream::{self, Stream};
use rust_embed::RustEmbed;
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::sync::Arc;
use tokio::sync::broadcast;
use tower_http::cors::CorsLayer;
use tracing::{info, error};

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

pub struct DashboardState {
    pub targets: Arc<dashmap::DashMap<String, TargetHost>>,
    pub findings_tx: broadcast::Sender<Finding>,
    pub ram_limit_mb: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DashboardStats {
    pub ram_mb: u64,
    pub ram_limit_mb: u64,
    pub active_threads: usize,
    pub active_proxies: usize,
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

async fn get_targets(State(state): State<Arc<DashboardState>>) -> Json<Vec<serde_json::Value>> {
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
    State(state): State<Arc<DashboardState>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let mut rx = state.findings_tx.subscribe();

    let stream = stream::unfold(rx, move |mut rx| async move {
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
                        return Some((Ok(Event::default().data(data)), rx));
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
    
    DashboardStats {
        ram_mb: sys.used_memory() / 1024 / 1024,
        ram_limit_mb: state.ram_limit_mb,
        active_threads: 0, // Simplified for now
        active_proxies: 0,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SERVER LIFECYCLE
// ─────────────────────────────────────────────────────────────────────────────

pub async fn start_dashboard(state: Arc<DashboardState>, port: u16) {
    let app = Router::new()
        .route("/", get(serve_index))
        .route("/index.html", get(serve_index))
        .route("/:path", get(serve_asset))
        .route("/api/v1/targets", get(get_targets))
        .route("/api/v1/findings/stream", get(findings_stream))
        .layer(CorsLayer::permissive())
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
