use crate::utils::{stealth_http::StealthClientBuilder, proxy::ProxyManager};
use crate::models::{TargetHost, TargetStatus, TargetType};
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
    proxy_manager: Arc<ProxyManager>,
}

impl OobInteractionManager {
    pub fn new(proxy_manager: Arc<ProxyManager>) -> Self {
        let server_url = std::env::var("INTERACTSH_SERVER_URL")
            .unwrap_or_else(|_| OOB_DEFAULT_SERVER.to_string());
        let token = std::env::var("INTERACTSH_TOKEN").ok();

        Self {
            server_url,
            token,
            proxy_manager,
        }
    }

    pub fn generate_id(&self) -> String {
        uuid::Uuid::new_v4().to_string().replace("-", "")[..16].to_string()
    }

    pub fn get_oob_domain(&self, id: &str) -> String {
        format!("{}.{}", id, self.server_url)
    }

    pub async fn poll_hits(&self, id: &str) -> Result<Vec<OobInteraction>> {
        // MOCK INTERFACE: En entornos reales, interactsh-client se usa via CLI
        // o via una API REST si el servidor lo soporta.
        // Aquí implementamos la lógica de polling via HTTP (asumiendo interactsh-server API)
        
        let poll_url = if let Some(ref token) = self.token {
             format!("https://{}/poll?id={}&token={}", self.server_url, id, token)
        } else {
             format!("https://{}/poll?id={}", self.server_url, id)
        };

        // We use a dummy target for the stealth client builder to satisfy proxy requirements
        let dummy_target = TargetHost {
            host: self.server_url.clone(),
            ip: None,
            resolved_ip: None,
            status: TargetStatus::Pending,
            target_type: TargetType::Web,
            file_path: None,
            user: None,
            findings: Arc::new(Vec::new()),
            tool_suggestions: Arc::new(Vec::new()),
            tactical_context: Arc::new(serde_json::json!({})),
            extra_data: Arc::new(serde_json::json!({})),
            version: 0,
            skip_heavy_scan: false,
            scan_id: None,
            scope_id: String::new(),
        };

        let client = StealthClientBuilder::build(&dummy_target, &self.proxy_manager)?;
        
        let res_val: Result<reqwest::Response, reqwest::Error> = client.get(&poll_url).send().await;
        match res_val {
            Ok(res) if res.status().is_success() => {
                let data: InteractshPollResponse = res.json().await?;
                Ok(data.interactions)
            }
            _ => Ok(Vec::new()),
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
