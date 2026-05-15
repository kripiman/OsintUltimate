use axum::{
    extract::FromRequestParts,
    http::StatusCode,
};
use axum::http::request::Parts;
use axum::async_trait;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc};
use ed25519_dalek::{Signature, Verifier};
use crate::models::{TargetHost, Finding};
use super::models::{DashboardAuth, MissionRequest};

pub struct DashboardState {
    pub targets: Arc<dashmap::DashMap<String, TargetHost>>,
    pub findings_tx: broadcast::Sender<Finding>,
    pub ram_limit_mb: u64,
    pub approval_gate: Option<Arc<crate::core::approval_gate::ApprovalGate>>,
    pub budget: Option<Arc<crate::core::orchestrator::swarm::TokenBudget>>,
    pub auth: Arc<DashboardAuth>,
    pub mission_tx: Option<Arc<mpsc::Sender<MissionRequest>>>,
    pub discord_webhook_url: Option<String>,
    pub credentials: Arc<dashmap::DashMap<String, super::models::CredentialStatus>>,
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

        if token_bytes.len() != 96 { 
            return Err((StatusCode::UNAUTHORIZED, "Invalid token length".to_string()));
        }

        let (payload, signature_bytes) = token_bytes.split_at(32);
        let signature = Signature::from_slice(signature_bytes)
            .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid signature format".to_string()))?;

        state.auth.verifying_key.verify(payload, &signature)
            .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid cryptographic signature".to_string()))?;

        let session_id = &payload[0..16];
        if session_id != state.auth.session_id {
            return Err((StatusCode::UNAUTHORIZED, "Token session mismatch".to_string()));
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
