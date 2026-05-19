/// handlers/mobile.rs — Item 15 from PLAN v3 6.B mapping table.
/// pub async fn submit_mobile_scan (L305–L420)
use axum::{
    extract::State,
    response::IntoResponse,
};
use axum::http::StatusCode;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;

use super::super::state::{DashboardState, ValidatedOperator};
use super::super::models::MissionRequest;

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

            let safe_name = std::path::Path::new(&filename)
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("upload.bin")
                .to_string();

            let uuid = uuid::Uuid::new_v4();
            let temp_dir = std::path::PathBuf::from("/tmp/osint_scans").join(uuid.to_string());

            if tokio::fs::create_dir_all(&temp_dir).await.is_err() {
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

                if file.write_all(&chunk).await.is_err() {
                    return (StatusCode::INTERNAL_SERVER_ERROR, "Error escribiendo archivo").into_response();
                }
            }

            if file.flush().await.is_err() {
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
