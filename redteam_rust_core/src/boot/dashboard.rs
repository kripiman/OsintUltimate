use crate::boot::cli::Args;
use redteam_rust_core::models::{TargetHost, TargetStatus};
use redteam_rust_core::core::engine::RedTeamEngine;
use redteam_rust_core::utils::config::Config;
use tracing::{info, warn, error};
use std::sync::Arc;

pub async fn setup_dashboard(
    args: &Args,
    utils_config: &Config,
    engine: &RedTeamEngine,
    dashboard_findings_tx: tokio::sync::broadcast::Sender<redteam_rust_core::models::Finding>,
    dashboard_targets: Arc<dashmap::DashMap<String, TargetHost>>,
    injection_tx: tokio::sync::mpsc::Sender<TargetHost>,
    certstream_kws_tx: Option<tokio::sync::mpsc::Sender<Vec<String>>>
) {
    if let Some(port) = args.dashboard {
        use redteam_rust_core::core::web::{DashboardState, DashboardAuth, MissionRequest, generate_dashboard_token};
        use ed25519_dalek::SigningKey;
        use rand::RngCore;

        let (tx, targets) = (dashboard_findings_tx.clone(), dashboard_targets.clone());

        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let mut session_id = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut session_id);

        let auth = std::sync::Arc::new(DashboardAuth {
            verifying_key: signing_key.verifying_key(),
            session_id,
        });

        let token = generate_dashboard_token(&signing_key, session_id, 86400);

        // Securely write token to workspace/logs/dashboard.token (Sprint 1)
        let logs_dir = std::path::PathBuf::from(&utils_config.workspace_dir).join("logs");
        let token_path = logs_dir.join("dashboard.token");
        let _ = tokio::fs::create_dir_all(&logs_dir).await;

        use std::os::unix::fs::OpenOptionsExt;
        match std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(&token_path)
        {
            Ok(mut file) => {
                use std::io::Write;
                let _ = file.write_all(token.as_bytes());
                info!("🔑 [DASHBOARD-AUTH] Token de acceso guardado de forma segura en {}", token_path.display());
            },
            Err(e) => warn!("⚠️ [DASHBOARD-AUTH] No se pudo guardar el token en disco ({}). No disponible para el operador.", e),
        }

        let (mission_tx, mut mission_rx) = tokio::sync::mpsc::channel::<MissionRequest>(32);
        let injection_tx_for_dashboard = injection_tx.clone();
        let cli_scope_id_mission = Arc::new(args.scope_id.clone().unwrap_or_default());

        tokio::spawn(async move {
            let cli_scope_id = cli_scope_id_mission;
            while let Some(mission) = mission_rx.recv().await {
                let target = match mission.target {
                    Some(ref t) if !t.is_empty() => t.clone(),
                    _ => {
                        warn!("⚠️ [MISSION-QUEUE] Received mission without target. Skipping.");
                        continue;
                    }
                };

                if let Some(cs_tx) = &certstream_kws_tx {
                    let mut kws = Vec::new();
                    for scope in &mission.in_scope {
                        let clean = scope.trim_start_matches("*.").to_lowercase();
                        if let Some(base) = clean.split('.').next() {
                            if !base.is_empty() {
                                kws.push(base.to_string());
                            }
                        }
                    }
                    if !kws.is_empty() {
                        let _ = cs_tx.send(kws).await;
                    }
                }

                info!("📡 [MISSION-QUEUE] Received mission for: {}. Injecting into pipeline...", target);
                
                let target_type = if target.contains("://") || target.contains('.') { redteam_rust_core::models::TargetType::Web }
                else if target.contains(':') { redteam_rust_core::models::TargetType::Network }
                else { redteam_rust_core::models::TargetType::Host };

                let host = TargetHost {
                    host: target,
                    ip: None,
                    resolved_ip: None,
                    status: TargetStatus::Pending,
                    target_type,
                    file_path: mission.apk,
                    user: None,
                    findings: Arc::new(Vec::new()),
                    tool_suggestions: Arc::new(Vec::new()),
                    tactical_context: Arc::new(serde_json::json!({
                        "program_name": mission.program_name,
                        "in_scope": mission.in_scope,
                        "out_of_scope": mission.out_of_scope,
                        "profile": mission.profile,
                        "stealth": mission.stealth,
                        "vuln_scan": mission.vuln_scan,
                        "oob_enabled": mission.oob_enabled,
                    })),
                    extra_data: Arc::new(serde_json::json!({})),
                    version: 0,
                    skip_heavy_scan: false,
                    scan_id: None, 
                    scope_id: mission.authorized_scope
                        .filter(|s| !s.trim().is_empty())
                        .unwrap_or_else(|| (*cli_scope_id).clone()),
                };

                // Determine if we should push to local stream OR to database queue
                let is_oracle = std::env::var("ORACLE_OVERRIDE").is_err() && 
                                tokio::fs::metadata("/run/mimikri/oracle_detected").await.is_ok();
                
                if let Ok(db_url) = std::env::var("DATABASE_URL") {
                    let pool_res = sqlx::PgPool::connect(&db_url).await;
                    if let Ok(pool) = pool_res {
                        let res = sqlx::query(
                            "INSERT INTO scan_queue (host, target_type, tactical_context, priority, status, worker_profile) VALUES ($1, $2, $3, $4, 'pending', 'scan')"
                        )
                        .bind(&host.host)
                        .bind(format!("{:?}", host.target_type))
                        .bind(&*host.tactical_context)
                        .bind(1i32)
                        .execute(&pool)
                        .await;
                        
                        match res {
                            Ok(_) => {
                                info!("📦 [MISSION-QUEUE] Saved mission directly to Postgres for Distributed Swarm: {}", host.host);
                                // REMOVED 'continue' - we WANT to fall through to inject into the local stream
                            }
                            Err(e) => {
                                warn!("⚠️ [MISSION-QUEUE] Failed DB insert, falling back to local stream: {}", e);
                            }
                        }
                    }
                }

                if let Err(e) = injection_tx_for_dashboard.send(host).await {
                    error!("❌ [MISSION-QUEUE] Failed to inject target into pipeline: {}", e);
                }
            }
        });

        let dashboard_state = std::sync::Arc::new(DashboardState {
            targets,
            findings_tx: tx,
            ram_limit_mb: utils_config.hard_memory_limit_mb as u64,
            approval_gate: Some(engine.approval_gate()),
            budget: None,
            auth: auth.clone(),
            mission_tx: Some(std::sync::Arc::new(mission_tx)),
            discord_webhook_url: utils_config.discord_webhook_url.clone(),
            credentials: std::sync::Arc::new(dashmap::DashMap::new()),
        });
        tokio::spawn(redteam_rust_core::core::web::start_dashboard(dashboard_state, port));
    }
}
