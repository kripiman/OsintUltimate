use crate::utils::proxy::ProxyManager;
use crate::models::constants::*;
use anyhow::Result;
use std::sync::Arc;
use tokio::time::{sleep, Duration};
use tracing::{info, warn};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OobInteraction {
    pub protocol: String,
    #[serde(rename = "remote-address")]
    pub remote_address: String,
    pub timestamp: String,
    #[serde(rename = "raw-request")]
    pub data: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct InteractshPollResponse {
    pub interactions: Vec<OobInteraction>,
}

pub struct OobInteractionManager {
    server_url: String,
    token: Option<String>,
    #[allow(dead_code)]
    proxy_manager: Arc<ProxyManager>,
}

impl OobInteractionManager {
    pub fn new(proxy_manager: Arc<ProxyManager>) -> Self {
        let raw = std::env::var("INTERACTSH_SERVER_URL")
            .unwrap_or_else(|_| OOB_DEFAULT_SERVER.to_string());
        let server_url = raw
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .trim_end_matches('/')
            .to_string();
        let token = std::env::var("INTERACTSH_TOKEN").ok();

        Self {
            server_url,
            token,
            proxy_manager,
        }
    }

    /// Constructor with explicit server URL (allows mock servers in integration tests).
    pub fn with_server_url(proxy_manager: Arc<ProxyManager>, server_url: String) -> Self {
        let token = std::env::var("INTERACTSH_TOKEN").ok();
        let server_url = server_url
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .trim_end_matches('/')
            .to_string();
        Self {
            server_url,
            token,
            proxy_manager,
        }
    }

    pub fn generate_id(&self) -> String {
        uuid::Uuid::new_v4().to_string().replace("-", "")[..16].to_string()
    }

    /// Deterministic OOB ID derived from scan_queue.id for correlation.
    pub fn generate_id_for_queue(queue_id: i64) -> String {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(queue_id.to_le_bytes());
        let result = hasher.finalize();
        format!("{:016x}", u64::from_le_bytes(result[0..8].try_into().unwrap()))
    }

    pub fn get_oob_domain(&self, id: &str) -> String {
        format!("{}.{}", id, self.server_url)
    }

    pub async fn poll_hits(&self, id: &str) -> Result<Vec<OobInteraction>> {
        // MOCK INTERFACE: En entornos reales, interactsh-client se usa via CLI
        // o via una API REST si el servidor lo soporta.
        // Aquí implementamos la lógica de polling via HTTP (asumiendo interactsh-server API)
        
        let scheme = if self.server_url.contains("127.0.0.1") || self.server_url.contains("localhost") {
            "http"
        } else {
            "https"
        };
        let poll_url = if let Some(ref token) = self.token {
             format!("{}://{}/poll?id={}&token={}", scheme, self.server_url, id, token)
        } else {
             format!("{}://{}/poll?id={}", scheme, self.server_url, id)
        };

        // OOB polling uses a plain reqwest client — no stealth required for infra-internal calls.
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .danger_accept_invalid_certs(true)
            .build()?;
        
        let res = client.get(&poll_url).send().await?;
        if res.status().is_success() {
            let data: InteractshPollResponse = res.json().await?;
            Ok(data.interactions)
        } else {
            warn!("[OOB] Poll returned HTTP {}", res.status());
            Ok(Vec::new())
        }
    }

    /// Verificación bloqueante con timeout
    pub async fn wait_for_interaction(&self, id: &str, timeout_secs: u64) -> Result<Option<OobInteraction>> {
        let start = std::time::Instant::now();
        let interval = Duration::from_millis(OOB_DEFAULT_POLL_INTERVAL_MS);
        
        info!("⏳ [OOB] Iniciando polling para ID: {} (Timeout: {}s)", id, timeout_secs);
        
        while start.elapsed().as_secs() < timeout_secs {
            match self.poll_hits(id).await {
                Ok(hits) if !hits.is_empty() => {
                    info!("🎯 [OOB] HIT DETECTADO para ID: {}!", id);
                    return Ok(Some(hits[0].clone()));
                }
                Err(e) => {
                    warn!("[OOB] Error consultando servidor: {}", e);
                }
                _ => {}
            }
            sleep(interval).await;
        }
        
        info!("💤 [OOB] Timeout alcanzado para ID: {}. No se detectaron interacciones.", id);
        Ok(None)
    }
}
