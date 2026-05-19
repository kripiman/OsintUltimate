/// handlers/reports.rs — Item 10 from PLAN v3 6.B mapping table.
/// pub async fn export_report (L200–L250)
use axum::{
    extract::State,
    response::Response,
    body::Body,
    Json,
};
use axum::http::{StatusCode, header};
use std::sync::Arc;

use super::super::state::{DashboardState, ValidatedOperator};
use super::super::models::ExportRequest;
use crate::utils::bounty_exporter::BountyExporter;

pub async fn export_report(
    _auth: ValidatedOperator,
    State(state): State<Arc<DashboardState>>,
    Json(req): Json<ExportRequest>,
) -> Response {
    let all_findings: Vec<_> = state.targets.iter()
        .flat_map(|kv| kv.value().findings.iter().cloned().collect::<Vec<_>>())
        .collect();

    let refs: Vec<&crate::models::Finding> = all_findings.iter().collect();
    let markdown = BountyExporter::generate(&refs, &req.platform);

    if let Some(ref webhook_url) = state.discord_webhook_url {
        let platform_name = req.platform.display_name();
        let count = refs.iter()
            .filter(|f| matches!(f.severity, crate::models::Severity::High | crate::models::Severity::Critical))
            .count();

        let payload = serde_json::json!({
            "username": "Mimikri Sentinel",
            "embeds": [{
                "title": format!("📤 Report Exported — {}", platform_name),
                "color": 0x00CC66,
                "description": format!("**{} High/Critical findings** exported to {} format.", count, platform_name),
                "footer": { "text": "Mimikri Bounty Exporter" },
                "timestamp": chrono::Utc::now().to_rfc3339()
            }]
        });

        let url = webhook_url.clone();
        tokio::spawn(async move {
            let _ = reqwest::Client::new().post(&url).json(&payload).send().await;
        });
    }

    let filename = req.platform.filename().to_string();
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/markdown; charset=utf-8")
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{}\"", filename),
        )
        .body(Body::from(markdown))
        .unwrap_or_else(|_| {
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::empty())
                .unwrap()
        })
}
