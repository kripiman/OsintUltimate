use crate::boot::cli::Args;
use redteam_rust_core::models::TargetHost;
use redteam_rust_core::core::factory::EngineFactory;
use redteam_rust_core::core::engine::{RedTeamEngine, app::EngineConfig};
use redteam_rust_core::core::capability_layer::ScanLayer;
use redteam_rust_core::utils::config::Config;
use redteam_rust_core::plugins::reporting::platform_client::PlatformClient;
use redteam_rust_core::models::ReportPlatform;
use tracing::{info, error};
use anyhow::{Result, Context};
use std::sync::Arc;
use std::time::Duration;
use redteam_rust_core::plugins::intelligence::nvd_monitor::NvdMonitor;
use redteam_rust_core::utils::cve_cache::CveCacheManager;

pub async fn dispatch(args: Args) -> Result<()> {
    if args.update_cve_cache {
        let db_url = args.postgres_url.clone()
            .or_else(|| std::env::var("DATABASE_URL").ok())
            .context("--update-cve-cache requires --postgres-url or DATABASE_URL env var")?;
        let pool = sqlx::PgPool::connect(&db_url).await?;
        CveCacheManager::init(pool);
        let monitor = NvdMonitor::new();
        let findings = monitor.poll().await?;
        info!("CVE cache updated: {} new CVEs", findings.len());
        return Ok(());
    }

    if args.worker {
        return crate::boot::worker::run_worker_mode(&args).await;
    }

    // --- ENQUEUE-ONLY MODE (V15.6): Queue targets for DO workers without local scanning ---
    if args.enqueue_only {
        let db_url = args.postgres_url.clone()
            .or_else(|| std::env::var("DATABASE_URL").ok())
            .context("--enqueue-only requires --postgres-url or DATABASE_URL env var")?;
        let pool = sqlx::PgPool::connect(&db_url).await?;
        let scope_id = args.scope_id.clone().unwrap_or_default();
        let tactical_context = serde_json::json!({"scope_id": scope_id});

        let mut targets: Vec<(String, String)> = Vec::new();
        if let Some(input_path) = &args.input {
            let file = tokio::fs::File::open(input_path).await?;
            let reader = tokio::io::BufReader::new(file);
            let mut lines = tokio::io::AsyncBufReadExt::lines(reader);
            while let Ok(Some(line)) = lines.next_line().await {
                let t = line.trim();
                if t.is_empty() { continue; }
                if !redteam_rust_core::utils::validate_target(t) {
                    error!("❌ Skipping invalid target: {}", t);
                    continue;
                }
                let target_type = if t.contains("://") || t.contains('.') { "Web".to_string() }
                    else if t.contains(':') { "Network".to_string() }
                    else { "Host".to_string() };
                targets.push((t.to_string(), target_type));
            }
        } else if let Some(target) = &args.target {
            if !redteam_rust_core::utils::validate_target(target) {
                anyhow::bail!("Invalid target provided: {}", target);
            }
            let target_type = if target.contains("://") || target.contains('.') { "Web".to_string() }
                else if target.contains(':') { "Network".to_string() }
                else { "Host".to_string() };
            targets.push((target.clone(), target_type));
        } else {
            anyhow::bail!("--enqueue-only requires --target or --input");
        }

        let mut enqueued = 0u64;
        for (host, target_type) in targets {
            let res = sqlx::query(
                "INSERT INTO scan_queue (host, target_type, tactical_context, priority, status, worker_profile) VALUES ($1, $2, $3, $4, 'pending', 'scan')"
            )
            .bind(&host)
            .bind(&target_type)
            .bind(&tactical_context)
            .bind(1i32)
            .execute(&pool)
            .await;
            match res {
                Ok(_) => {
                    info!("📦 ENQUEUED: {} ({}) -> scan_queue", host, target_type);
                    enqueued += 1;
                }
                Err(e) => error!("❌ FAILED to enqueue {}: {}", host, e),
            }
        }
        info!("✅ ENQUEUE COMPLETE: {} targets queued for DO workers. Exiting.", enqueued);
        return Ok(());
    }

    // --- ENGINE INITIALIZATION ---
    let (hw, auto_concurrency, _soft_limit, _hard_limit) = EngineFactory::detect_infrastructure_limits();
    let utils_config = Config::from_env();
    
    let concurrency = if args.concurrency == 10 || args.concurrency > auto_concurrency {
        info!("Adjusting concurrency to {} based on detected hardware profile.", auto_concurrency);
        auto_concurrency
    } else {
        args.concurrency
    };

    let ollama_url = if args.ollama_url == "http://localhost:11434" {
        utils_config.ollama_url.clone()
    } else {
        args.ollama_url.clone()
    };

    let max_tokens = if args.max_tokens == 5000 {
        utils_config.max_tokens
    } else {
        args.max_tokens
    };

    info!("🚀 Mimikri Core v0.1.0 starting...");
    info!("Hardware Detected: {:?} (Cores: {}, RAM: {}MB)", hw.infra_type, hw.cores, hw.ram_mb);
    info!("Infrastructure limits: Soft={}MB, Hard={}MB", utils_config.soft_memory_limit_mb, utils_config.hard_memory_limit_mb);

    let proxies: Vec<String> = args.proxies.as_ref()
        .map(|s| s.split(',').map(|p| p.trim().to_string()).filter(|p| !p.is_empty()).collect())
        .unwrap_or_default();

    let max_layer = match args.max_layer.to_lowercase().as_str() {
        "passive" => ScanLayer::Passive,
        "discovery" => ScanLayer::Discovery,
        "scanning" => ScanLayer::Scanning,
        "verification" => ScanLayer::Verification,
        "exploitation" => ScanLayer::Exploitation,
        "post-exploitation" | "post-exp" => ScanLayer::PostExploitation,
        _ => ScanLayer::Scanning,
    };

    // V15.6 ORACLE BAN-PREVENTION GATE: Fail-closed on OCI for active layers
    let oracle_override = std::env::var("ORACLE_OVERRIDE").map(|v| v == "1").unwrap_or(false);
    if !oracle_override && !args.worker && !args.enqueue_only {
        if redteam_rust_core::utils::stealth_detect::is_oracle_cloud().await {
            if max_layer >= ScanLayer::Scanning {
                anyhow::bail!(
                    "🚨 ORACLE BAN-PREVENTION GATE: Active scan layer '{}' is BLOCKED on Oracle Cloud. \
                    nmap/raw sockets violate OCI TOS. \
                    Options: (1) --enqueue-only to queue for DO workers, (2) --max-layer passive|discovery, (3) run on DO droplet with --worker, (4) ORACLE_OVERRIDE=1 to bypass (DANGER).",
                    max_layer.description()
                );
            }
            if args.target.is_some() || args.input.is_some() {
                tracing::warn!(
                    "⚠️ ORACLE OPSEC: Target/input specified on Oracle Cloud. Traffic will originate from OCI IP. \
                    Use --enqueue-only to delegate to DO workers, or ensure --max-layer is passive/discovery only."
                );
            }
        }
    }

    let (dashboard_findings_tx, _) = tokio::sync::broadcast::channel::<redteam_rust_core::models::Finding>(1024);
    let dashboard_targets = std::sync::Arc::new(dashmap::DashMap::<String, TargetHost>::new());

    let engine_config = EngineConfig {
        concurrency,
        ollama_url,
        max_tokens,
        stealth: args.stealth,
        insecure: args.insecure,
        scripts: args.scripts.clone(),
        service_detection: args.service_detection,
        scan_type: args.scan_type.clone(),
        fragment: args.fragment,
        decoy: args.decoy.clone(),
        ports: args.ports.clone(),
        vuln_scan: args.vuln_scan,
        dns_servers: args.dns_servers.as_ref().map(|s| s.split(',').map(|ip| ip.trim().to_string()).collect()),
        doh: args.doh,
        proxies: if proxies.is_empty() { None } else { Some(proxies) },
        plugins_dir: args.plugins_dir.clone(),
        dashboard_port: args.dashboard,
        max_layer,
        readiness_timeout: Duration::from_secs(180), // V13 Default: 3 min for DO exit nodes
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
        policy_file: utils_config.policy_file.clone(),
        strict_scope: utils_config.strict_scope,
        nuclei_auto_update: utils_config.nuclei_auto_update,
        h1_username: utils_config.h1_username.clone(),
        h1_api_key: utils_config.h1_api_key.clone(),
        bugcrowd_api_key: utils_config.bugcrowd_api_key.clone(),
        intigriti_token: utils_config.intigriti_token.clone(),
        bb_program_handle: utils_config.bb_program_handle.clone(),
        dashboard_tx: Some(dashboard_findings_tx.clone()),
        dashboard_targets: Some(dashboard_targets.clone()),
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

    let engine = RedTeamEngine::from_config(engine_config.clone(), &utils_config);
    
    // --- SCOPE SYNCHRONIZATION (V15.1) ---
    if std::env::var("SCOPE_SYNC").map(|v| v == "true").unwrap_or(false) {
        let has_any_platform = engine_config.h1_api_key.is_some() || engine_config.intigriti_token.is_some();
        if has_any_platform {
            let policy_file = engine_config.policy_file.clone().unwrap_or_else(|| "policy.json".to_string());
            let mut syncer = redteam_rust_core::core::policy::scope_syncer::ScopeSyncer::new(
                engine.policy(),
                std::path::PathBuf::from(policy_file),
            );

            // Register HackerOne client
            if let Some(ref h1_key) = engine_config.h1_api_key {
                let h1_client = PlatformClient::new(
                    ReportPlatform::HackerOne,
                    h1_key.clone(),
                    engine_config.h1_username.clone(),
                );
                syncer.add_client(h1_client, engine_config.h1_username.clone().unwrap_or_default());
            }

            // Register Intigriti client (handle format: "companyHandle/programHandle")
            if let Some(ref inti_key) = engine_config.intigriti_token {
                let inti_client = PlatformClient::new(
                    ReportPlatform::Intigriti,
                    inti_key.clone(),
                    None,
                );
                let handle = engine_config.bb_program_handle.clone().unwrap_or_default();
                syncer.add_client(inti_client, handle);
            }

            info!("🔱 V15.1 SCOPE: Initializing scope synchronization...");
            if let Err(e) = syncer.sync().await {
                error!("❌ V15.1 SCOPE: Initial sync failed: {}", e);
            }

            // Periodic sync every 4 hours
            let syncer_loop = Arc::new(syncer);
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(14400));
                loop {
                    interval.tick().await;
                    let _ = syncer_loop.sync().await;
                }
            });
        }
    }

    crate::boot::stealth::init(&engine, &args, &utils_config).await?;

    // V15.6 ORACLE COORDINATOR: Auto-spawn DO workers when queue has pending jobs
    if !args.worker && !args.enqueue_only {
        if redteam_rust_core::utils::stealth_detect::is_oracle_cloud().await {
            if let (Some(db_url), Ok(do_token)) = (args.postgres_url.clone().or_else(|| std::env::var("DATABASE_URL").ok()), utils_config.require_do_token()) {
                let db_url_clone = db_url.clone();
                let do_token_clone = do_token.clone();
                let pm_clone = engine.proxy_manager().clone();
                let do_client = Arc::new(redteam_rust_core::infrastructure::digital_ocean::DigitalOceanClient::new(do_token_clone, pm_clone));
                let do_client_reap = do_client.clone();

                // Auto-spawn task
                tokio::spawn(async move {
                    let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
                    loop {
                        interval.tick().await;
                        let pool_res = sqlx::PgPool::connect(&db_url_clone).await;
                        if let Ok(pool) = pool_res {
                            let pending: Option<(i64,)> = sqlx::query_as("SELECT COUNT(*) FROM scan_queue WHERE status = 'pending'")
                                .fetch_optional(&pool).await.ok().flatten();
                            let workers: Option<(i64,)> = sqlx::query_as("SELECT COUNT(*) FROM workers WHERE status = 'active' AND last_seen > NOW() - INTERVAL '2 minutes'")
                                .fetch_optional(&pool).await.ok().flatten();
                            if let (Some((pending_count,)), Some((worker_count,))) = (pending, workers) {
                                if pending_count > 0 && worker_count == 0 {
                                    tracing::info!("🚀 ORACLE COORDINATOR: {} pending jobs, 0 active workers. Spawning DO ephemeral worker...", pending_count);
                                    match do_client.create_worker_droplet(&format!("mimikri-worker-{:x}", rand::random::<u32>()), "nyc1").await {
                                        Ok(droplet) => {
                                            tracing::info!("✅ ORACLE COORDINATOR: Spawned worker droplet {} (ID: {})", droplet.name, droplet.id);
                                        }
                                        Err(e) => {
                                            tracing::error!("❌ ORACLE COORDINATOR: Failed to spawn DO worker: {}", e);
                                        }
                                    }
                                }
                            }
                        }
                    }
                });

                // Reaper task: destroy off/orphan droplets every 5 min
                tokio::spawn(async move {
                    let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
                    loop {
                        interval.tick().await;
                        match do_client_reap.reap_stale_droplets().await {
                            Ok(0) => {}
                            Ok(n) => tracing::info!("🛡️ REAPER: Destroyed {} stale/off DO droplets", n),
                            Err(e) => tracing::error!("❌ REAPER: Failed to reap droplets: {}", e),
                        }
                    }
                });
            }
        }
    }

    let sink = crate::boot::sink_setup::build_multi_sink(&args, &engine_config, &utils_config, &engine).await?;

    // --- DASHBOARD ---
    let (injection_tx, injection_rx) = tokio::sync::mpsc::channel::<TargetHost>(100);
    let (certstream_kws_tx, certstream_kws_rx) = tokio::sync::mpsc::channel::<Vec<String>>(10);
    crate::boot::dashboard::setup_dashboard(
        &args,
        &utils_config,
        &engine,
        dashboard_findings_tx,
        dashboard_targets,
        injection_tx,
        Some(certstream_kws_tx)
    ).await;

    // --- TARGETS ---
    let target_hosts = crate::boot::targets::build_target_stream(&args, &utils_config, injection_rx, Some(certstream_kws_rx)).await?;

    // --- EXECUTION ---
    if args.autonomous {
        engine.run_autopilot(target_hosts, sink).await?;
    } else {
        engine.run_pipeline(target_hosts, sink, args.swarm).await?;
    }

    // --- FINALIZATION ---
    redteam_rust_core::utils::generate_report(&args.jsonl_output, &args.html_output).await.ok();

    Ok(())
}
