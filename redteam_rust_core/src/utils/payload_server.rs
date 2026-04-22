use anyhow::Result;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use std::collections::HashMap;
use uuid::Uuid;
use tracing::{info, warn};

pub struct PayloadServer {
    staged_payloads: Arc<RwLock<HashMap<String, PathBuf>>>,
}

impl Default for PayloadServer {
    fn default() -> Self {
        Self::new()
    }
}

impl PayloadServer {
    pub fn new() -> Self {
        Self {
            staged_payloads: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn stage_payload(&self, payload_path: PathBuf) -> String {
        let token = Uuid::new_v4().to_string();
        let mut payloads = self.staged_payloads.write().await;
        payloads.insert(token.clone(), payload_path);
        token
    }

    pub async fn start(self) -> Result<u16> {

        use axum::{Router, extract::Path, response::IntoResponse, http::StatusCode};
        use tower_http::services::ServeFile;
        
        let payloads = self.staged_payloads.clone();
        
        let app = Router::new()
            .route("/:token", axum::routing::get(move |Path(token): Path<String>| async move {
                let mut payloads = payloads.write().await;
                if let Some(path) = payloads.remove(&token) {
                    match ServeFile::new(path).try_call(axum::http::Request::new(())).await {
                        Ok(response) => {
                            info!("🎁 OTT: Payload {} descargado. Token invalidado.", token);
                            response.into_response()
                        },
                        Err(_) => (StatusCode::NOT_FOUND, "File not found").into_response(),
                    }
                } else {
                    (StatusCode::NOT_FOUND, "Token not found or already used").into_response()
                }
            }));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
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