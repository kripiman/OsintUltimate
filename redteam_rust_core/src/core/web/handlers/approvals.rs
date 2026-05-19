/// handlers/approvals.rs — Items 12, 13, 14 from PLAN v3 6.B mapping table.
/// pub async fn get_approvals            (L259–L278)
/// pub struct ApprovalDecisionPayload    (L280–L285)
/// pub async fn post_approval_decision   (L287–L303)
use axum::{
    extract::{State, Path},
    response::IntoResponse,
    Json,
};
use axum::http::StatusCode;
use std::sync::Arc;

use super::super::state::{DashboardState, ValidatedOperator};

pub async fn get_approvals(
    _auth: ValidatedOperator,
    State(state): State<Arc<DashboardState>>,
) -> Json<Vec<serde_json::Value>> {
    if let Some(gate) = &state.approval_gate {
        let approvals: Vec<serde_json::Value> = gate.pending_approvals.iter().map(|kv| {
            let req = kv.value();
            serde_json::json!({
                "id": req.id,
                "action": req.action,
                "risk_level": req.risk_level,
                "reason": req.reason,
                "requested_by": req.requested_by,
            })
        }).collect();
        Json(approvals)
    } else {
        Json(vec![])
    }
}

#[derive(serde::Deserialize)]
pub struct ApprovalDecisionPayload {
    pub decision: String,
    pub reason: String,
    pub handover_payload: Option<String>,
}

pub async fn post_approval_decision(
    ValidatedOperator(user): ValidatedOperator,
    State(state): State<Arc<DashboardState>>,
    Path(id): Path<String>,
    Json(payload): Json<ApprovalDecisionPayload>,
) -> impl IntoResponse {
    if let Some(gate) = &state.approval_gate {
        if payload.decision == "approve" {
            let _ = gate.approve(&id, &user, &payload.reason, payload.handover_payload).await;
        } else {
            let _ = gate.reject(&id, &user, &payload.reason).await;
        }
        (StatusCode::OK, "Decision recorded").into_response()
    } else {
        (StatusCode::BAD_REQUEST, "Approval gate not configured").into_response()
    }
}
