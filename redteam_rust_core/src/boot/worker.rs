use crate::boot::cli::Args;
use redteam_rust_core::models::{TargetHost, TargetStatus};
use redteam_rust_core::core::engine::{RedTeamEngine, app::EngineConfig};
use redteam_rust_core::core::sink::{MultiSink, PostgresSink};
use redteam_rust_core::core::capability_layer::ScanLayer;
use redteam_rust_core::utils::config::Config;
use tracing::{info, error};
use anyhow::{Result, Context};
use std::time::Duration;
use std::str::FromStr;
use std::sync::Arc;

pub async fn run_worker_mode(args: &Args) -> Result<()> {
    let cli_scope_id = Arc::new(args.scope_id.clone().unwrap_or_default());
    let db_url = args.postgres_url.as_ref().context("Postgres URL is required for worker mode (--postgres-url)")?;
    let node_id = args.node_id.clone().unwrap_or_else(|| {
        format!("node-{}", std::process::id())
    });

    info!("🐝 [Worker] Starting in distributed mode. Node ID: {}", node_id);
    let pool = sqlx::PgPool::connect(db_url).await?;

    // Register node
    sqlx::query("INSERT INTO workers (id, status) VALUES ($1, 'active') ON CONFLICT(id) DO UPDATE SET last_seen = NOW(), status = 'active'")
        .bind(&node_id)
        .execute(&pool)
        .await?;

    let utils_config = Config::from_env();
    
    loop {
        // Poll for a job
        let job: Option<(i32, String, String, serde_json::Value)> = sqlx::query_as(
            "UPDATE scan_queue SET status = 'claimed', claimed_by = $1, updated_at = NOW() 
             WHERE id = (
                 SELECT id FROM scan_queue 
                 WHERE status = 'pending' 
                 ORDER BY priority DESC, created_at ASC 
                 LIMIT 1 FOR UPDATE SKIP LOCKED
             ) RETURNING id, host, target_type, tactical_context"
        )
        .bind(&node_id)
        .fetch_optional(&pool)
        .await?;

        if let Some((id, host, target_type, tactical_context)) = job {
            info!("📦 [Worker] Claimed job {}: {} ({})", id, host, target_type);
            
            // Re-use engine setup logic from main
            let engine_config = EngineConfig {
                concurrency: args.concurrency,
                insecure: args.insecure,
                stealth: args.stealth,
                service_detection: args.service_detection,
                scan_type: args.scan_type.clone(),
                fragment: args.fragment,
                decoy: args.decoy.clone(),
                ports: args.ports.clone(),
                vuln_scan: args.vuln_scan,
                max_tokens: args.max_tokens,
                ollama_url: utils_config.ollama_url.clone(),
                policy_file: utils_config.policy_file.clone(),
                strict_scope: utils_config.strict_scope,
                nuclei_auto_update: utils_config.nuclei_auto_update,
                h1_username: utils_config.h1_username.clone(),
                h1_api_key: utils_config.h1_api_key.clone(),
                bugcrowd_api_key: utils_config.bugcrowd_api_key.clone(),
                intigriti_token: utils_config.intigriti_token.clone(),
                bb_program_handle: utils_config.bb_program_handle.clone(),
                scripts: args.scripts.clone(),
                dns_servers: args.dns_servers.as_ref().map(|s| s.split(',').map(|i| i.trim().to_string()).collect()),
                doh: args.doh,
                proxies: args.proxies.as_ref().map(|s| s.split(',').map(|i| i.trim().to_string()).collect()),
                plugins_dir: args.plugins_dir.clone(),
                max_layer: ScanLayer::from_str(&args.max_layer).unwrap_or(ScanLayer::Scanning),
                dashboard_port: args.dashboard,
                readiness_timeout: std::time::Duration::from_secs(60),
                proxy_mode: utils_config.proxy_mode,
                proxy_pool_size: utils_config.proxy_pool_size,
                mcp_token: utils_config.mcp_token.clone(),
                mobsf_url: utils_config.mobsf_url.clone(),
                mobsf_api_key: utils_config.mobsf_api_key.clone(),
                mobsf_timeout_secs: utils_config.mobsf_timeout_secs,
                vigil_url: utils_config.vigil_url.clone(),
                vigil_api_key: utils_config.vigil_api_key.clone(),
                rebuff_url: utils_config.rebuff_url.clone(),
                rebuff_api_token: utils_config.rebuff_api_token.clone(),
                dashboard_tx: None,
                dashboard_targets: None,
                clairvoyance_wordlist_path: utils_config.clairvoyance_wordlist_path.clone(),
                shuffledns_resolvers_path: utils_config.shuffledns_resolvers_path.clone(),
                shuffledns_wordlist_path: utils_config.shuffledns_wordlist_path.clone(),
                ssrfmap_path: utils_config.ssrfmap_path.clone(),
                nosqlmap_path: utils_config.nosqlmap_path.clone(),
                ghauri_path: utils_config.ghauri_path.clone(),
                gopherus_path: utils_config.gopherus_path.clone(),
                kxss_path: utils_config.kxss_path.clone(),
                s3scanner_path: utils_config.s3scanner_path.clone(),
                s3scanner_wordlist_path: utils_config.s3scanner_wordlist_path.clone(),
                shuffledns_path: utils_config.shuffledns_path.clone(),
                massdns_path: utils_config.massdns_path.clone(),
                sliver_ca_path: utils_config.sliver_ca_path.clone(),
                sliver_cert_path: utils_config.sliver_cert_path.clone(),
                sliver_key_path: utils_config.sliver_key_path.clone(),
                sliver_server_addr: utils_config.sliver_server_addr.clone(),
                workspace_dir: utils_config.workspace_dir.clone(),
            };

            let engine = RedTeamEngine::from_config(engine_config, &utils_config);
            
            let target = TargetHost {
                host: host.clone(),
                ip: None,
                resolved_ip: None,
                status: TargetStatus::Pending,
                target_type: serde_json::from_str(&format!("\"{}\"", target_type)).unwrap_or(redteam_rust_core::models::TargetType::Web),
                file_path: None,
                user: None,
                findings: Arc::new(Vec::new()),
                tool_suggestions: Arc::new(Vec::new()),
                tactical_context: Arc::new(tactical_context),
                extra_data: Arc::new(serde_json::json!({})),
                version: 0,
                skip_heavy_scan: false,
                scan_id: None, 
                scope_id: (*cli_scope_id).clone(),
            };

            let mut multi_sink = MultiSink::new();
            multi_sink.add(Box::new(PostgresSink::new(db_url).await?));
            
            // Add BountySink if credentials present
            if utils_config.h1_api_key.is_some() || utils_config.bugcrowd_api_key.is_some() || utils_config.intigriti_token.is_some() {
                multi_sink.add(Box::new(redteam_rust_core::core::sink::BountySink::new(
                    utils_config.h1_username.clone(),
                    utils_config.h1_api_key.clone(),
                    utils_config.bugcrowd_api_key.clone(),
                    utils_config.intigriti_token.clone(),
                    utils_config.bb_program_handle.clone(),
                )));
            }

            let target_stream = Box::pin(futures::stream::once(async move { target }));
            match engine.run_autopilot(target_stream, Box::new(multi_sink)).await {
                Ok(_) => {
                    info!("✅ [Worker] Completed job {}", id);
                    sqlx::query("UPDATE scan_queue SET status = 'completed', updated_at = NOW() WHERE id = $1")
                        .bind(id)
                        .execute(&pool)
                        .await?;
                },
                Err(e) => {
                    error!("❌ [Worker] Job {} failed: {}", id, e);
                    sqlx::query("UPDATE scan_queue SET status = 'failed', updated_at = NOW() WHERE id = $1")
                        .bind(id)
                        .execute(&pool)
                        .await?;
                }
            }
        } else {
            // No jobs, sleep
            tokio::time::sleep(Duration::from_secs(5)).await;
            
            // Keep-alive for worker node
            let _ = sqlx::query("UPDATE workers SET last_seen = NOW() WHERE id = $1")
                .bind(&node_id)
                .execute(&pool)
                .await;
        }
    }
}
