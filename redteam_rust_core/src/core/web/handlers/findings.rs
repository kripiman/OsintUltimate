/// handlers/findings.rs — Items 4, 6, 16, 17 from PLAN v3 6.B mapping table.
/// pub async fn findings_stream     (L68–L102)
/// pub async fn get_stats_handler   (L121–L126)
/// pub async fn get_metrics         (L422–L436)
/// pub async fn get_roi_rankings    (L438–L455)
use axum::{
    extract::State,
    response::sse::{Event, KeepAlive, Sse},
    Json,
};
use futures::stream::{self, Stream};
use std::convert::Infallible;
use std::sync::Arc;
use tokio::sync::broadcast;

use super::super::state::{DashboardState, ValidatedOperator};
use super::super::models::DashboardStats;
use super::get_current_stats;

pub async fn findings_stream(
    _auth: ValidatedOperator,
    State(state): State<Arc<DashboardState>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = state.findings_tx.subscribe();

    let stream = stream::unfold((rx, state), |(mut rx, state)| async move {
        loop {
            match rx.recv().await {
                Ok(finding) => {
                    let stats = get_current_stats(&state);
                    let event = serde_json::json!({
                        "type": "finding",
                        "payload": {
                            "tool": "Engine",
                            "severity": format!("{:?}", finding.severity),
                            "title": finding.title,
                            "category": format!("{:?}", finding.category),
                        },
                        "stats": stats,
                    });

                    if let Ok(data) = serde_json::to_string(&event) {
                        return Some((Ok(Event::default().data(data)), (rx, state)));
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(_) => break,
            }
        }
        None
    });

    Sse::new(stream).keep_alive(KeepAlive::default())
}

pub async fn get_stats_handler(
    _auth: ValidatedOperator,
    State(state): State<Arc<DashboardState>>,
) -> Json<DashboardStats> {
    Json(get_current_stats(&state))
}

pub async fn get_metrics(
    _auth: ValidatedOperator,
) -> Json<serde_json::Value> {
    use crate::utils::telemetry::*;
    use std::sync::atomic::Ordering;

    Json(serde_json::json!({
        "findings_in": METRIC_FINDINGS_IN.load(Ordering::Relaxed),
        "fpf_drops": METRIC_FPF_DROPS.load(Ordering::Relaxed),
        "local_qwen": METRIC_LOCAL_QWEN_TRIAGE.load(Ordering::Relaxed),
        "mid_calls": METRIC_MID_LLM_CALLS.load(Ordering::Relaxed),
        "premium_calls": METRIC_PREMIUM_LLM_CALLS.load(Ordering::Relaxed),
        "manual_submissions": METRIC_MANUAL_SUBMISSIONS.load(Ordering::Relaxed),
    }))
}

pub async fn get_roi_rankings(
    _auth: ValidatedOperator,
) -> Json<Vec<(String, f64)>> {
    use crate::core::selection::ProgramAnalyzer;
    let analyzer = ProgramAnalyzer::new();

    let programs = match analyzer.load_from_json("config/programs.json") {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!("⚠️ ProgramAnalyzer: Failed to load config/programs.json ({}). Dashboard ROI will be empty.", e);
            vec![]
        }
    };

    let rankings = analyzer.rank_programs(programs);
    Json(rankings)
}
