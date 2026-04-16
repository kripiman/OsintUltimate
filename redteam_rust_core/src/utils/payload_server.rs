use anyhow::Result;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use std::collections::HashMap;
use uuid::Uuid;
use tracing::{info, warn};

pub struct PayloadServer {
    staged_payloads: Arc<RwLock<HashMap<String, PathBuf>>>,
    server_handle: Option<tokio::task::JoinHandle<()>>,
}

impl PayloadServer {
    pub fn new() -> Self {
        Self {
            staged_payloads: Arc::new(RwLock::new(HashMap::new())),
            server_handle: None,
        }
    }

    pub fn stage_payload(&self, payload_path: PathBuf) -> String {
        let token = Uuid::new_v4().to_string();
        let payloads = self.staged_payloads.clone();
        
        tokio::spawn(async move {
            payloads.write().await.insert(token.clone(), payload_path);
        });
        
        token
    }

    pub async fn start(self) -> Result<u16> {
        use std::net::SocketAddr;
        use axum::{Router, extract::Path, response::{Response, IntoResponse}, http::StatusCode};
        use tower_http::services::ServeFile;
        
        let payloads = self.staged_payloads.clone();
        
        let app = Router::new()
            .route("/:token", axum::routing::get(move |Path(token): Path<String>| async move {
                let payloads = payloads.read().await;
                if let Some(path) = payloads.get(&token) {
                    match ServeFile::new(path).try_call(axum::http::Request::new(())).await {
                        Ok(response) => response.into_response(),
                        Err(_) => (StatusCode::NOT_FOUND, "File not found").into_response(),
                    }
                } else {
                    (StatusCode::NOT_FOUND, "Token not found").into_response()
                }
            }));

        let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await?;
        let port = listener.local_addr()?.port();
        
        info!("🚀 SOVEREIGN: Payload server listening on port {}", port);
        
        tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, app).await {
                warn!("Payload server error: {}", e);
            }
        });
        
        Ok(port)
    }
}