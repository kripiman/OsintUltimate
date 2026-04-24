#![warn(clippy::all)]

pub mod menu;

use clap::Parser;
use std::sync::Arc;
use std::time::Duration;
use redteam_rust_core::models::{TargetHost, TargetStatus};
use redteam_rust_core::core::factory::EngineFactory;
use redteam_rust_core::core::engine::{RedTeamEngine, app::EngineConfig};
use redteam_rust_core::core::sink::{MultiSink, JsonlSink, SqliteSink, TacticalWebhookSink, DataSink};
use redteam_rust_core::core::capability_layer::ScanLayer;
use redteam_rust_core::utils::config::Config;
use redteam_rust_core::utils::validate_target;
use redteam_rust_core::utils::security::is_ssrf_safe_host_async;
use tracing::{info, error, warn};
use anyhow::{Context, Result};
use futures::StreamExt;

#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    pub target: Option<String>,
    #[arg(short, long)]
    pub input: Option<String>,
    #[arg(short, long, default_value = "scan_result.jsonl")]
    pub jsonl_output: String,
    #[arg(long, default_value = "scan_report.html")]
    pub html_output: String,
    #[arg(long)]
    pub sqlite_output: Option<String>,
    #[arg(short, long, default_value_t = 10)]
    pub concurrency: usize,
    #[arg(long)]
    pub scripts: Option<String>,
    #[arg(long, default_value_t = false)]
    pub stealth: bool,
    #[arg(long, default_value_t = false)]
    pub service_detection: bool,
    #[arg(long, default_value_t = false)]
    pub insecure: bool,
    #[arg(long)]
    pub dns_servers: Option<String>,
    #[arg(long)]
    pub proxies: Option<String>,
    #[arg(long)]
    pub otel_endpoint: Option<String>,
    #[arg(long, default_value_t = false)]
    pub json_logs: bool,
    #[arg(long, value_name = "DIR")]
    pub plugins_dir: Option<String>,
    #[arg(long, default_value = "sS")]
    pub scan_type: String,
    #[arg(long, default_value_t = false)]
    pub fragment: bool,
    #[arg(long)]
    pub decoy: Option<String>,
    #[arg(long, default_value_t = false)]
    pub doh: bool,
    #[arg(short, long)]
    pub ports: Option<String>,
    #[arg(long, default_value_t = false, help = "Activate professional vulnerability hunting profile (OS detection, version-intensity 9, NSE vuln/exploit/auth/default/discovery, 5000 top ports)")]
    pub vuln_scan: bool,
    #[arg(long, default_value_t = false, help = "Activate Autonomous AI Agent (Sentinel)")]
    pub autonomous: bool,
    #[arg(long, default_value = "http://localhost:11434")]
    pub ollama_url: String,
    #[arg(long, default_value = "Scanning")]
    pub max_layer: String,
    #[arg(long, help = "Enable real-time web dashboard (port)")]
    pub dashboard: Option<u16>,
    #[arg(long, default_value_t = false, help = "Activate Multi-Agent Swarm Mode (V4.0)")]
    pub swarm: bool,
    #[arg(long, default_value_t = 5000, help = "Maximum tokens allowed per scan job")]
    pub max_tokens: u32,
    #[arg(long, help = "Start MCP (Model Context Protocol) Server via SSE")]
    pub mcp_server: bool,
    #[arg(long, default_value_t = 3001)]
    pub mcp_port: u16,
    #[arg(short = 'P', long, default_value_t = false, help = "Activate autonomous persistence phase (Decepticon Fase 5)")]
    pub persist: bool,
    #[arg(short = 'C', long, default_value_t = false, help = "Activate post-exploit consolidation phase")]
    pub consolidate: bool,
}

// End of file cleanup

#[tokio::main]
async fn main() -> Result<()> { 
    dotenv::dotenv().ok();

    let mut args = Args::parse();
    if std::env::args().len() <= 1 {
        if let Some(menu_args) = crate::menu::show_menu()? {
            args = menu_args;
        } else {
            anyhow::bail!("Operación cancelada por el usuario o configuración vacía.");
        }
    }

    // Initialize Telemetry
    redteam_rust_core::utils::init_telemetry(args.otel_endpoint.clone(), args.json_logs, None)
        .context("Failed to initialize telemetry")?;

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

    info!("🚀 OSINT Ultimate Core v0.1.0 starting...");
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
    };

    let engine = RedTeamEngine::from_config(engine_config, &utils_config);

    // --- STEALTH INFRASTRUCTURE SETUP (V14.1) ---
    if let Ok(token) = utils_config.require_do_token() {
        engine.init_stealth_infrastructure(token.clone()).await?;

        // Global Kill-Switch Integration
        let token_clean = token.clone();
        let pm_clean = engine.proxy_manager();
        tokio::spawn(async move {
            tokio::signal::ctrl_c().await.ok();
            warn!("⚠️ [KILL-SWITCH] Interrupt detected. Commencing autonomous cleanup of all ephemeral egress nodes...");
            let do_client = redteam_rust_core::infrastructure::digital_ocean::DigitalOceanClient::new(token_clean, pm_clean);
            if let Err(e) = do_client.destroy_all_ephemeral_droplets().await {
                error!("❌ [KILL-SWITCH] Failed to clean up DigitalOcean droplets: {}", e);
            } else {
                info!("🛡️ [KILL-SWITCH] Cleanup complete. Sovereign egress terminated safely.");
            }
            std::process::exit(0);
        });
    }


    // --- SINK SETUP ---
    let mut multi_sink = MultiSink::new();
    if let Some(ref db_path) = args.sqlite_output {
        multi_sink.add(Box::new(SqliteSink::new(db_path).await?));
    } else {
        multi_sink.add(Box::new(JsonlSink::new(&args.jsonl_output).await?));
    }

    if let Ok(c2_env) = std::env::var("C2_URL") {
        if let Ok(parsed_url) = url::Url::parse(&c2_env) {
            if parsed_url.scheme() == "https" && is_ssrf_safe_host_async(parsed_url.host_str().unwrap_or("")).await {
                let c2_token = std::env::var("C2_TOKEN").ok();
                multi_sink.add(Box::new(TacticalWebhookSink::new(parsed_url.to_string(), c2_token, engine.proxy_manager())?));
            }
        }
    }

    // --- DISCORD NOTIFICATIONS (V14.1 Quick Alerts) ---
    if let Some(webhook_url) = utils_config.discord_webhook_url.clone() {
        if webhook_url.starts_with("https://discord.com/api/webhooks/") {
            use redteam_rust_core::core::notifications::discord::DiscordSink;
            multi_sink.add(Box::new(DiscordSink::new(webhook_url, engine.proxy_manager())));
            info!("🔔 [DiscordSink] Notification routing attached for High/Critical findings.");
        }
    }

    // --- ACTIVITY LOG (TIMELINE) ---
    // V15: Quick Win integration to ensure timeline.jsonl is populated automatically
    let timeline_path = std::path::PathBuf::from("workspace/logs/timeline.jsonl");
    if let Ok(activity_log) = redteam_rust_core::utils::activity_log::ActivityLog::new(timeline_path).await {
        let act_log_arc = std::sync::Arc::new(activity_log);
        multi_sink.add(Box::new(redteam_rust_core::core::sink::TimelineSink::new(act_log_arc)));
        info!("📝 [TimelineSink] Acitivity log routing attached.");
    } else {
        warn!("⚠️ [TimelineSink] Failed to initialize ActivityLog at workspace/logs/timeline.jsonl");
    }

    // --- DASHBOARD ---
    if let Some(port) = args.dashboard {
        use redteam_rust_core::core::web::{DashboardState, DashboardAuth, MissionRequest, generate_dashboard_token};
        use ed25519_dalek::SigningKey;
        use rand::RngCore;

        let (tx, targets) = (tokio::sync::broadcast::channel(1024).0, std::sync::Arc::new(dashmap::DashMap::new()));

        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let mut session_id = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut session_id);

        let auth = std::sync::Arc::new(DashboardAuth {
            verifying_key: signing_key.verifying_key(),
            session_id,
        });

        let token = generate_dashboard_token(&signing_key, session_id, 86400);

        // Securely write token to workspace/logs/dashboard.token (Sprint 1)
        let token_path = "workspace/logs/dashboard.token";
        let _ = tokio::fs::create_dir_all("workspace/logs").await;

        use std::os::unix::fs::OpenOptionsExt;
        match std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(token_path)
        {
            Ok(mut file) => {
                use std::io::Write;
                let _ = file.write_all(token.as_bytes());
                info!("🔑 [DASHBOARD-AUTH] Token de acceso guardado de forma segura en {}", token_path);
            },
            Err(e) => warn!("⚠️ [DASHBOARD-AUTH] No se pudo guardar el token en disco ({}). No disponible para el operador.", e),
        }

        let (mission_tx, mut mission_rx) = tokio::sync::mpsc::channel::<MissionRequest>(32);

        tokio::spawn(async move {
            while let Some(mission) = mission_rx.recv().await {
                info!("📡 [MISSION-QUEUE] Target={} Profile={} Program={}", mission.target, mission.profile, mission.program_name);
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
        });
        tokio::spawn(redteam_rust_core::core::web::start_dashboard(dashboard_state, port));
    }

    // --- TARGETS ---
    let target_stream: futures::stream::BoxStream<'static, String> = if let Some(input_path) = args.input.clone() {
        let file = tokio::fs::File::open(&input_path).await?;
        let reader = tokio::io::BufReader::new(file);
        tokio_stream::wrappers::LinesStream::new(tokio::io::AsyncBufReadExt::lines(reader))
            .filter_map(|res| async move { 
                res.ok().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()) 
            })
            .boxed()
    } else if let Some(target) = args.target.clone() {
        Box::pin(futures::stream::iter(vec![target]))
    } else {
        anyhow::bail!("Either --target or --input must be provided.");
    };

    let target_hosts: futures::stream::BoxStream<'static, TargetHost> = target_stream
        .filter(|t: &String| { 
            let t_clone = t.clone();
            let valid = validate_target(&t_clone); 
            if !valid { error!("❌ Skipping invalid target: {}", t_clone); } 
            async move { valid } 
        })
        .map(|t: String| {
            let target_type = if t.contains("://") || t.contains('.') { redteam_rust_core::models::TargetType::Web }
            else if t.contains(':') { redteam_rust_core::models::TargetType::Network }
            else { redteam_rust_core::models::TargetType::Host };

            TargetHost {
                host: t, ip: None, resolved_ip: None, status: TargetStatus::Pending, target_type,
                user: None,
                findings: Arc::new(Vec::new()), tool_suggestions: Arc::new(Vec::new()),
                tactical_context: Arc::new(serde_json::json!({})), extra_data: Arc::new(serde_json::json!({})),
            }
        }).boxed();

    // --- EXECUTION ---
    let sink: Box<dyn DataSink> = Box::new(multi_sink);
    if args.autonomous {
        engine.run_autopilot(target_hosts, sink).await?;
    } else {
        engine.run_pipeline(target_hosts, sink, args.swarm).await?;
    }

    // --- FINALIZATION ---
    redteam_rust_core::utils::generate_report(&args.jsonl_output, &args.html_output).await.ok();

    redteam_rust_core::utils::shutdown_telemetry();
    Ok(())
}
