use axum::{
    extract::{State, Path, Query},
    response::sse::{Event, KeepAlive, Sse},
    response::Response,
    body::Body,
    Json,
};
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;
use futures::stream::{self, Stream};
use std::convert::Infallible;
use std::sync::Arc;
use tokio::sync::broadcast;
use tokio::io::AsyncWriteExt;

use super::state::{DashboardState, ValidatedOperator};
use super::models::{DashboardStats, ExportRequest, MissionRequest, SwarmAgentStatus, SwarmStatusResponse};
use crate::utils::bounty_exporter::BountyExporter;

#[derive(serde::Deserialize)]
pub struct TargetsQuery {
    pub since: Option<u64>,
}

pub async fn get_targets(
    _auth: ValidatedOperator,
    Query(query): Query<TargetsQuery>,
    State(state): State<Arc<DashboardState>>
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
    State(state): State<Arc<DashboardState>>
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

pub fn get_current_stats(state: &DashboardState) -> DashboardStats {
    let mut sys = sysinfo::System::new_all();
    sys.refresh_all();
    
    let tokens = state.budget.as_ref().map(|b| b.current_total()).unwrap_or(0);
    let limit = state.budget.as_ref().map(|b| b.max_tokens).unwrap_or(0);

    DashboardStats {
        ram_mb: sys.used_memory() / 1024 / 1024,
        ram_limit_mb: state.ram_limit_mb,
        active_threads: 0, 
        active_proxies: 0,
        tokens_used: tokens,
        token_limit: limit,
    }
}

pub async fn get_stats_handler(
    _auth: ValidatedOperator,
    State(state): State<Arc<DashboardState>>
) -> Json<DashboardStats> {
    Json(get_current_stats(&state))
}

pub async fn get_swarm_status(
    _auth: ValidatedOperator,
    State(state): State<Arc<DashboardState>>
) -> Json<SwarmStatusResponse> {
    let tokens = state.budget.as_ref().map(|b| b.current_total()).unwrap_or(0);
    let limit = state.budget.as_ref().map(|b| b.max_tokens).unwrap_or(0);

    let agents = vec![
        SwarmAgentStatus { role: "Planner".to_string(), status: "Waiting".to_string(), last_action: "Initial analysis".to_string() },
        SwarmAgentStatus { role: "Scout".to_string(), status: "Idle".to_string(), last_action: "Port scan".to_string() },
        SwarmAgentStatus { role: "Exploiter".to_string(), status: "Idle".to_string(), last_action: "Vulnerability check".to_string() },
        SwarmAgentStatus { role: "Reporter".to_string(), status: "Idle".to_string(), last_action: "Drafting report".to_string() },
    ];

    Json(SwarmStatusResponse {
        agents,
        total_tokens: tokens,
        max_tokens: limit,
    })
}

pub async fn get_attack_graph(
    _auth: ValidatedOperator,
    State(state): State<Arc<DashboardState>>
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
            "username": "OsintUltimate Sentinel",
            "embeds": [{
                "title": format!("📤 Report Exported — {}", platform_name),
                "color": 0x00CC66,
                "description": format!("**{} High/Critical findings** exported to {} format.", count, platform_name),
                "footer": { "text": "OsintUltimate Bounty Exporter" },
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

pub async fn get_containers(_auth: ValidatedOperator) -> Json<Vec<serde_json::Value>> {
    Json(vec![
        serde_json::json!({"id": "osint-sandbox-1", "image": "distroless-python", "status": "running", "cpu": "2%", "memory": "45MB"}),
        serde_json::json!({"id": "osint-sandbox-2", "image": "blackarch-minimal", "status": "idle", "cpu": "0%", "memory": "12MB"}),
    ])
}

pub async fn get_approvals(
    _auth: ValidatedOperator,
    State(state): State<Arc<DashboardState>>
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

pub async fn submit_mobile_scan(
    _auth: ValidatedOperator,
    State(state): State<Arc<DashboardState>>,
    mut multipart: axum::extract::Multipart,
) -> impl IntoResponse {
    let mut file_path = None;
    let mut autonomous = false;
    let mut notes = String::new();

    while let Ok(Some(mut field)) = multipart.next_field().await {
        let name = field.name().unwrap_or_default().to_string();
        if name == "file" {
            let filename = field.file_name().unwrap_or("app.apk").to_string();
            let lower = filename.to_lowercase();
            if !lower.ends_with(".apk") && !lower.ends_with(".ipa") {
                return (StatusCode::BAD_REQUEST, "Solo se permiten archivos .apk o .ipa").into_response();
            }

            // Fix 1: Path Traversal Sanitization
            let safe_name = std::path::Path::new(&filename)
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("upload.bin")
                .to_string();

            let uuid = uuid::Uuid::new_v4();
            let temp_dir = std::path::PathBuf::from("/tmp/osint_scans").join(uuid.to_string());
            
            // Fix 3: Async I/O (tokio::fs)
            if let Err(_) = tokio::fs::create_dir_all(&temp_dir).await {
                return (StatusCode::INTERNAL_SERVER_ERROR, "Error creando sandbox").into_response();
            }

            let path = temp_dir.join(safe_name);
            let mut file = match tokio::fs::File::create(&path).await {
                Ok(f) => f,
                Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Error creando archivo").into_response(),
            };

            let mut bytes_written = 0;
            let mut magic_checked = false;
            let mut header_buf = Vec::with_capacity(2);

            // Fix 2: Streaming Upload to prevent OOM
            while let Ok(Some(chunk)) = field.chunk().await {
                if !magic_checked {
                    header_buf.extend_from_slice(&chunk);
                    if header_buf.len() >= 2 {
                        if &header_buf[0..2] != b"PK" {
                            drop(file);
                            let _ = tokio::fs::remove_dir_all(&temp_dir).await;
                            return (StatusCode::BAD_REQUEST, "Firma de archivo inválida (no es un ZIP/APK/IPA)").into_response();
                        }
                        magic_checked = true;
                    }
                }

                bytes_written += chunk.len();
                if bytes_written > 500 * 1024 * 1024 {
                    drop(file);
                    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
                    return (StatusCode::PAYLOAD_TOO_LARGE, "Archivo excede límite de 500MB").into_response();
                }

                if let Err(_) = file.write_all(&chunk).await {
                    return (StatusCode::INTERNAL_SERVER_ERROR, "Error escribiendo archivo").into_response();
                }
            }

            if let Err(_) = file.flush().await {
                return (StatusCode::INTERNAL_SERVER_ERROR, "Error sincronizando archivo").into_response();
            }

            if bytes_written == 0 {
                let _ = tokio::fs::remove_dir_all(&temp_dir).await;
                return (StatusCode::BAD_REQUEST, "Archivo vacío").into_response();
            }

            file_path = Some(path.to_string_lossy().to_string());
        } else if name == "autonomous" {
            let val = field.text().await.unwrap_or_default();
            autonomous = val == "true" || val == "1";
        } else if name == "notes" {
            notes = field.text().await.unwrap_or_default();
        }
    }

    let path = match file_path {
        Some(p) => p,
        None => return (StatusCode::BAD_REQUEST, "Campo 'file' ausente").into_response(),
    };

    let req = MissionRequest {
        target: None,
        apk: Some(path),
        program_name: "Mobile Audit".to_string(),
        in_scope: vec![],
        out_of_scope: vec![],
        profile: "Mobile".to_string(),
        stealth: false,
        vuln_scan: true,
        oob_enabled: false,
        use_swarm: autonomous,
        max_concurrency: 5,
        notes,
    };

    if let Some(tx) = &state.mission_tx {
        match tx.send(req).await {
            Ok(_) => (StatusCode::ACCEPTED, "Mobile scan queued").into_response(),
            Err(_) => (StatusCode::SERVICE_UNAVAILABLE, "Engine not ready").into_response(),
        }
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "Mission channel not configured").into_response()
    }
}
