use axum::{
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
    routing::{get, post},
    Router,
};
use axum::async_trait;
use tower_http::cors::{AllowOrigin, CorsLayer};
use std::{sync::Arc, time::Duration};
use std::sync::atomic::{AtomicU32, AtomicU64};
use tokio::sync::mpsc;
use tracing::info;
use crate::plugins::GlobalConfig;
use crate::core::mcp::sanitizer::DataSanitizer;
use crate::core::sink::PostgresSink;
use std::path::PathBuf;
use moka::future::Cache;
use dashmap::DashMap;

pub mod handlers;
pub mod tools;
pub mod execute;

/// The modularized MCP (Model Context Protocol) Server for Mimikri RedTeam Core.
pub struct McpServer {
    pub(crate) config: Arc<GlobalConfig>,
    pub(crate) sanitizer: Arc<DataSanitizer>,
    pub(crate) sessions: Arc<dashmap::DashMap<String, mpsc::Sender<axum::response::sse::Event>>>,
    pub(crate) db: Option<Arc<PostgresSink>>,
    pub(crate) plugin_cache: Cache<String, String>,
    pub(crate) file_hash_cache: Arc<DashMap<String, String>>,
    pub(crate) call_history: Arc<tokio::sync::Mutex<Vec<(String, String)>>>,
    pub(crate) checkpoint_manifest: Arc<DashMap<String, serde_json::Value>>,
    pub total_calls: AtomicU32,
    pub cache_hits: AtomicU32,
    pub tokens_saved: AtomicU64,
    pub bytes_processed: AtomicU64,
    pub off_path_engine: Option<Arc<crate::core::ai::off_path::OffPathAiEngine>>,
}

impl McpServer {
    pub fn new(config: GlobalConfig) -> Self {
        let plugin_cache = Cache::builder()
            .max_capacity(100)
            .time_to_live(Duration::from_secs(1800)) // 30 min TTL
            .build();

        Self {
            config: Arc::new(config),
            sanitizer: Arc::new(DataSanitizer::new()),
            sessions: Arc::new(dashmap::DashMap::new()),
            db: None,
            plugin_cache,
            file_hash_cache: Arc::new(DashMap::new()),
            call_history: Arc::new(tokio::sync::Mutex::new(Vec::with_capacity(20))),
            checkpoint_manifest: Arc::new(DashMap::new()),
            total_calls: AtomicU32::new(0),
            cache_hits: AtomicU32::new(0),
            tokens_saved: AtomicU64::new(0),
            bytes_processed: AtomicU64::new(0),
            off_path_engine: None,
        }
    }

    pub async fn with_postgres(mut self, path: PathBuf) -> Self {
        if let Ok(db) = PostgresSink::new(path).await {
            let stats_res = db.get_mcp_stats().await;
            if let Ok(stats) = stats_res {
                use std::sync::atomic::Ordering;
                if let Some(v) = stats.get("total_calls") { self.total_calls.store(*v as u32, Ordering::SeqCst); }
                if let Some(v) = stats.get("cache_hits") { self.cache_hits.store(*v as u32, Ordering::SeqCst); }
                if let Some(v) = stats.get("tokens_saved") { self.tokens_saved.store(*v as u64, Ordering::SeqCst); }
                if let Some(v) = stats.get("bytes_processed") { self.bytes_processed.store(*v as u64, Ordering::SeqCst); }
            }
            self.db = Some(Arc::new(db));
        }
        self
    }

    pub fn with_off_path_engine(mut self, engine: Arc<crate::core::ai::off_path::OffPathAiEngine>) -> Self {
        self.off_path_engine = Some(engine);
        self
    }

    pub async fn run(self, port: u16) -> anyhow::Result<()> {
        if self.config.mcp_token.is_none() || self.config.mcp_token.as_ref().unwrap().is_empty() {
            anyhow::bail!("CRITICAL: MCP_TOKEN not set in environment. MCP server cannot start without authentication.");
        }

        let state = Arc::new(self);
        
        let cors = CorsLayer::new()
            .allow_origin(AllowOrigin::predicate(move |origin, _| {
                let origin_str = origin.to_str().unwrap_or("");
                origin_str == format!("http://127.0.0.1:{}", port) || origin_str == format!("http://localhost:{}", port)
            }))
            .allow_methods([axum::http::Method::GET, axum::http::Method::POST])
            .allow_headers([axum::http::header::AUTHORIZATION, axum::http::header::CONTENT_TYPE]);

        let app = Router::new()
            .route("/sse", get(handlers::sse_handler))
            .route("/message/:session_id", post(handlers::message_handler))
            .layer(cors)
            .with_state(state);

        let addr = format!("127.0.0.1:{}", port);
        info!("🛡️ [MCP-Server] Escuchando en http://{} (SSE Enabled + AUTH + CORS Hardened)", addr);
        
        let listener = tokio::net::TcpListener::bind(&addr).await?;
        axum::serve(listener, app).await?;
        
        Ok(())
    }
}

pub struct ValidatedOperator;

#[async_trait]
impl FromRequestParts<Arc<McpServer>> for ValidatedOperator {
    type Rejection = (StatusCode, String);

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<McpServer>,
    ) -> Result<Self, Self::Rejection> {
        let auth_header = parts.headers.get("Authorization")
            .and_then(|h| h.to_str().ok())
            .ok_or((StatusCode::UNAUTHORIZED, "Missing Authorization header".to_string()))?;

        if !auth_header.starts_with("Bearer ") {
            return Err((StatusCode::UNAUTHORIZED, "Invalid Authorization header format".to_string()));
        }

        let token = &auth_header[7..];
        
        if let Some(valid_token) = &state.config.mcp_token {
            if token == valid_token {
                return Ok(ValidatedOperator);
            }
        }

        Err((StatusCode::UNAUTHORIZED, "Invalid MCP token".to_string()))
    }
}
