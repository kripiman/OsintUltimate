/// handlers/targets.rs — Items 1, 2, 3, 8 from PLAN v3 6.B mapping table.
/// pub struct TargetsQuery          (L20–L23)
/// pub async fn get_targets         (L25–L46)
/// pub async fn get_target_findings (L48–L66)
/// pub async fn get_attack_graph    (L149–L183)
use axum::{
    extract::{State, Path, Query},
    response::IntoResponse,
    Json,
};
use axum::http::StatusCode;
use std::sync::Arc;
use super::super::state::{DashboardState, ValidatedOperator};

#[derive(serde::Deserialize)]
pub struct TargetsQuery {
    pub since: Option<u64>,
}

pub async fn get_targets(
    _auth: ValidatedOperator,
    Query(query): Query<TargetsQuery>,
    State(state): State<Arc<DashboardState>>,
) -> Json<Vec<serde_json::Value>> {
    let since = query.since.unwrap_or(0);
    let targets: Vec<serde_json::Value> = state.targets.iter()
        .filter(|kv| kv.value().version > since)
        .map(|kv| {
            let t = kv.value();
            serde_json::json!({
                "host": t.host,
                "ip": t.ip,
                "status": format!("{:?}", t.status),
                "findings_count": t.findings.len(),
                "target_type": format!("{:?}", t.target_type),
                "version": t.version,
                "new_findings": t.findings_since(since),
            })
        }).collect();
    Json(targets)
}

pub async fn get_target_findings(
    _auth: ValidatedOperator,
    Path(host): Path<String>,
    Query(query): Query<TargetsQuery>,
    State(state): State<Arc<DashboardState>>,
) -> impl IntoResponse {
    let since = query.since.unwrap_or(0);
    let target = match state.targets.get(&host) {
        Some(t) => t,
        None => return (StatusCode::NOT_FOUND, "Target not found").into_response(),
    };

    let findings: Vec<crate::models::Finding> = target.findings.iter()
        .filter(|f| f.version > since)
        .cloned()
        .collect();

    Json(findings).into_response()
}

pub async fn get_attack_graph(
    _auth: ValidatedOperator,
    State(state): State<Arc<DashboardState>>,
) -> Json<serde_json::Value> {
    let mut nodes = Vec::new();
    let mut edges = Vec::new();

    for kv in state.targets.iter() {
        let t = kv.value();
        nodes.push(serde_json::json!({
            "id": t.host,
            "label": t.host,
            "type": "target",
            "severity": "Info"
        }));

        for f in t.findings.iter() {
            nodes.push(serde_json::json!({
                "id": f.id,
                "label": f.title,
                "type": "finding",
                "severity": format!("{:?}", f.severity)
            }));
            edges.push(serde_json::json!({
                "source": t.host,
                "target": f.id
            }));
        }
    }

    Json(serde_json::json!({
        "nodes": nodes,
        "links": edges
    }))
}
