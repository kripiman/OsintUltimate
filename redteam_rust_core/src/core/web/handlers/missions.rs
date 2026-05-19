/// handlers/missions.rs — Item 9 from PLAN v3 6.B mapping table.
/// pub async fn submit_mission (L185–L198)
use axum::{
    extract::State,
    response::IntoResponse,
    Json,
};
use axum::http::StatusCode;
use std::sync::Arc;

use super::super::state::{DashboardState, ValidatedOperator};
use super::super::models::MissionRequest;

pub async fn submit_mission(
    _auth: ValidatedOperator,
    State(state): State<Arc<DashboardState>>,
    Json(req): Json<MissionRequest>,
) -> impl IntoResponse {
    if let Some(tx) = &state.mission_tx {
        match tx.send(req).await {
            Ok(_) => (StatusCode::ACCEPTED, "Mission queued").into_response(),
            Err(_) => (StatusCode::SERVICE_UNAVAILABLE, "Engine not ready").into_response(),
        }
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "Mission channel not configured").into_response()
    }
}
