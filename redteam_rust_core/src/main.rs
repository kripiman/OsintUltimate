#![warn(clippy::all)]

pub mod menu;

use clap::Parser;
use std::sync::Arc;
use redteam_rust_core::models::{TargetHost, TargetStatus};
use redteam_rust_core::core::plugin_loader::DynamicPluginLoader;
use redteam_rust_core::utils::LivenessChecker; 
use tracing::{info, error, warn};
// use std::collections::HashSet; // Removed
use regex::Regex;
use anyhow::{Context, Result};
use once_cell::sync::Lazy;
use tokio_util::sync::CancellationToken;
use redteam_rust_core::core::capability_layer::{ScanLayer, ScanLayerPolicy};
use redteam_rust_core::core::approval_gate::ApprovalGate;
use redteam_rust_core::core::ai_cascade::{TieredAIRouter, RouteLevel};
use redteam_rust_core::core::agent::{OllamaClient, GeminiClient};

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
}

static TARGET_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[a-zA-Z0-9.-]+$").expect("TARGET_RE must be valid")
});

fn validate_target(target: &str) -> bool {
    TARGET_RE.is_match(target) && !target.starts_with('-')
}

#[tokio::main]
async fn main() -> Result<()> { 
    dotenv::dotenv().ok(); // Load environment variables from .env if present

    let mut args = Args::parse();
    if std::env::args().len() <= 1 {
        // Launch interactive menu if no arguments are provided
        if let Some(menu_args) = crate::menu::show_menu()? {
            args = menu_args;
        } else {
            anyhow::bail!("Operación cancelada por el usuario o configuración vacía.");
        }
    }
    let command_line = std::env::args().collect::<Vec<String>>().join(" ");

    // Initialize Telemetry
    redteam_rust_core::utils::init_telemetry(args.otel_endpoint.clone(), args.json_logs)
        .context("Failed to initialize telemetry")?;

    // --- ADAPTIVE INFRASTRUCTURE DETECTION ---
    let hw = redteam_rust_core::utils::detect_infrastructure();
    info!("Hardware Detected: {:?} (Cores: {}, RAM: {}MB)", hw.infra_type, hw.cores, hw.ram_mb);

    // Auto-adjust concurrency based on HW if not specified by user or if too high
    let (mut soft_limit, mut hard_limit) = (600, 900);
    
    match hw.infra_type {
        redteam_rust_core::utils::InfrastructureType::UltraLowMemory => {
            warn!("🚨 ULTRA-LOW MEMORY DETECTED: Optimizing for 1GB RAM minimum.");
            warn!("⚠️  ADVISORY: Running OsintUltimate via Docker on 1GB RAM is NOT recommended due to Docker overhead. Please run the native binary or ensure swaps are enabled.");
            if args.concurrency > 10 {
                warn!("Overriding user concurrency of {} to 10 for stability.", args.concurrency);
                args.concurrency = 10;
            }
            soft_limit = 500;
            hard_limit = 850;
        }
        redteam_rust_core::utils::InfrastructureType::LocalPC => {
            if args.concurrency > 30 {
                warn!("LocalPC detected. Capping concurrency at 30.");
                args.concurrency = 30;
            }
        }
        redteam_rust_core::utils::InfrastructureType::Server => {
            info!("Server-grade hardware detected. Scalable mode activated.");
            // Concurrency remains as user specified or default
        }
        redteam_rust_core::utils::InfrastructureType::Hybrid => {}
    }

    // Initialize Memory Monitor with dynamic limits
    let memory_monitor = Arc::new(redteam_rust_core::utils::MemoryMonitor::new(soft_limit, hard_limit));
    memory_monitor.start_logging();

    // 1. Determine Initial Targets
    let initial_targets: Vec<String> = if let Some(input_path) = args.input.clone() {
        use tokio::fs::File;
        use tokio::io::{BufReader, AsyncBufReadExt};
        let file = File::open(&input_path).await
            .with_context(|| format!("Failed to open input file: {}", input_path))?;
        let mut reader = BufReader::new(file).lines();
        let mut targets = Vec::new();
        while let Some(line) = reader.next_line().await? {
            if !line.trim().is_empty() {
                targets.push(line);
            }
        }
        targets
    } else if let Some(target) = args.target.clone() {
        vec![target]
    } else {
        anyhow::bail!("Either --target or --input must be provided.");
    };

    // Validate Targets
    let valid_targets: Vec<String> = initial_targets.iter()
        .filter(|t| {
            if validate_target(t) { true } else {
                error!("❌ Skipping invalid target: {}", t);
                false
            }
        })
        .cloned()
        .collect();

    if valid_targets.is_empty() {
        anyhow::bail!("No valid targets found. Please check your input.");
    }

    // V9 FIX (CRIT-010): Regex must accept 2-char scan types like "sS" (the default).
    // Format: 's' prefix + one valid Nmap scan type character.
    static SCAN_TYPE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^s[STAUYNFXW]$").expect("SCAN_TYPE_RE must be valid"));
    if !SCAN_TYPE_RE.is_match(&args.scan_type) {
        anyhow::bail!("Invalid --scan-type parameter '{}'. Must be a valid Nmap scan type (e.g., sS, sT, sU, sA).", args.scan_type);
    }

    // Initialize Shared LivenessChecker with DoH support
    let dns_servers: Option<Vec<String>> = args.dns_servers.as_ref().map(|s| {
        s.split(',').map(|ip| ip.trim().to_string()).filter(|ip| !ip.is_empty()).collect()
    });
    let liveness_checker = LivenessChecker::new(dns_servers, args.doh);

    // P1 FIX: Capability Warning early in the pipeline if attempting privileged scans
    if args.scan_type == "sS" && !redteam_rust_core::utils::common::check_cap_net_raw() {
         warn!("🚨 WARNING: Running without root/CAP_NET_RAW privileges. Nmap will silently degrade the stealth SYN scan (-sS) to a highly detectable TCP Connect scan (-sT).");
    }
    if args.vuln_scan && !redteam_rust_core::utils::common::check_cap_net_raw() {
         warn!("🚨 WARNING: --vuln-scan requires root/CAP_NET_RAW for OS detection (-O). OS fingerprinting will be skipped by Nmap.");
    }

    // Initialize Stealth Components
    // P0 FIX: Evasion mechanisms (Jitter and Proxies)
    let jitter = std::sync::Arc::new(redteam_rust_core::utils::common::HumanJitter::new(100, 1500));
    let mut proxy_manager = args.proxies.as_ref().map(|s| {
        let proxies_list = s.split(',').map(|p| p.trim().to_string()).filter(|p| !p.is_empty()).collect();
        std::sync::Arc::new(redteam_rust_core::utils::proxy::ProxyManager::new(proxies_list, args.insecure))
    });

    // --- INFRASTRUCTURE STEALTH UPGRADE ---
    let mut droplet_id: Option<u64> = None;
    let mut do_client: Option<redteam_rust_core::infrastructure::digital_ocean::DigitalOceanClient> = None;

    if args.stealth {
        let config = redteam_rust_core::utils::config::Config::from_env();
        if let Ok(token) = config.require_do_token() {
            info!("🛡️ STEALTH MODE: Initializing DigitalOcean ephemeral infrastructure...");
            let client = redteam_rust_core::infrastructure::digital_ocean::DigitalOceanClient::new(token);
            
            match client.create_droplet("osint-stealth-node", "nyc1").await {
                Ok(droplet) => {
                    info!("🚀 Droplet created (ID: {}). Waiting for IP...", droplet.id);
                    droplet_id = Some(droplet.id);
                    do_client = Some(client);
                    
                    match do_client.as_ref().unwrap().wait_for_ip(droplet.id).await {
                        Ok(ip) => {
                            info!("✅ Ephemeral Node Ready: {}", ip);
                            let do_proxy = redteam_rust_core::infrastructure::proxy::ProxyManager::from_droplet_ip(&ip);
                            let proxy_url = do_proxy.url();
                            
                            // Inject into the proxy manager
                            if let Some(ref pm) = proxy_manager {
                                pm.add_proxy(proxy_url);
                            } else {
                                // Create a new manager if none existed
                                proxy_manager = Some(std::sync::Arc::new(
                                    redteam_rust_core::utils::proxy::ProxyManager::new(vec![proxy_url], args.insecure)
                                ));
                            }
                        }
                        Err(e) => error!("❌ Failed to get Droplet IP: {}. Falling back to local IP.", e),
                    }
                }
                Err(e) => error!("❌ Failed to create Droplet: {}. Falling back to local IP.", e),
            }
        } else {
            warn!("⚠️ STEALTH flag active but DIGITALOCEAN_TOKEN not found. Using local IP with human-jitter only.");
        }
    }

    // Global Shutdown Token (CancellationToken is better than broadcast for hierarchies)
    let shutdown_token = CancellationToken::new();
    
    let shutdown_token_clone = shutdown_token.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        warn!("🛑 Graceful shutdown initiated. Cleaning up...");
        shutdown_token_clone.cancel();
    });

    // --- PIPELINE SETUP ---
    let mut multi_sink = redteam_rust_core::core::sink::MultiSink::new();

    if let Some(ref db_path) = args.sqlite_output {
        info!("🗄️ Using SQLite persistence at {}", db_path);
        multi_sink.add(Box::new(redteam_rust_core::core::SqliteSink::new(db_path).await?));
    } else {
        multi_sink.add(Box::new(redteam_rust_core::core::JsonlSink::new(&args.jsonl_output).await?));
    }

    // V10 C2 Bridge: Check for Webhook exfiltration
    if let Ok(c2_url) = std::env::var("C2_URL") {
        let c2_token = std::env::var("C2_TOKEN").ok();
        info!("📡 C2 READY: Tactical Webhook exfiltration enabled to {}", c2_url);
        multi_sink.add(Box::new(redteam_rust_core::core::sink::TacticalWebhookSink::new(c2_url, c2_token)));
    }

    let sink: Box<dyn redteam_rust_core::core::DataSink> = Box::new(multi_sink);

    let stealth_jitter = if args.stealth {
        Some(redteam_rust_core::utils::JitterSleep::for_stealth())
    } else {
        None
    };

    let mut builder = redteam_rust_core::core::Pipeline::builder()
        .concurrency(args.concurrency)
        .shutdown_token(shutdown_token)
        .liveness_checker(liveness_checker.clone())
        .command_line(command_line)
        .with_sink(sink)
        .with_jitter(stealth_jitter)
        .memory_monitor(memory_monitor.clone());

    // Initialize Capability Layer Policy
    let max_layer = match args.max_layer.to_lowercase().as_str() {
        "passive" => ScanLayer::Passive,
        "discovery" => ScanLayer::Discovery,
        "scanning" => ScanLayer::Scanning,
        "verification" => ScanLayer::Verification,
        "exploitation" => ScanLayer::Exploitation,
        "post-exploitation" | "post-exp" => ScanLayer::PostExploitation,
        _ => {
            warn!("Invalid --max-layer '{}', defaulting to Scanning", args.max_layer);
            ScanLayer::Scanning
        }
    };

    let policy = ScanLayerPolicy {
        max_layer,
        require_approval_for_layer_3_plus: true, 
        require_approval_for_layer_4_plus: true,
        require_approval_for_layer_5: true,
    };
    
    let approval_gate = Arc::new(ApprovalGate::for_red_team());
    
    builder = builder.policy(policy).approval_gate(approval_gate.clone());
    
    // --- DASHBOARD STARTUP ---
    if let Some(port) = args.dashboard {
        let (tx, targets) = (tokio::sync::broadcast::channel(1024).0, Arc::new(dashmap::DashMap::new()));
        builder = builder.with_dashboard(tx.clone(), targets.clone());
        
        let dashboard_state = Arc::new(redteam_rust_core::core::web_server::DashboardState {
            targets,
            findings_tx: tx,
            ram_limit_mb: hard_limit,
        });
        
        tokio::spawn(redteam_rust_core::core::web_server::start_dashboard(dashboard_state, port));
    }

    for p in redteam_rust_core::plugins::get_all_discovery() {
        builder = builder.with_discovery(p);
    }

    let config = redteam_rust_core::plugins::GlobalConfig {
        insecure: args.insecure,
        jitter: jitter.clone(),
        proxy_manager: proxy_manager.clone(),
        nmap_options: redteam_rust_core::plugins::NmapOptions {
            scripts: args.scripts.clone(),
            stealth: args.stealth,
            service_detection: args.service_detection,
            scan_type: args.scan_type.clone(),
            fragment: args.fragment,
            decoy: args.decoy.clone(),
            ports: args.ports.clone(),
            vuln_scan: args.vuln_scan,
        },
    };

    for p in redteam_rust_core::plugins::get_all_scanners(config) {
        builder = builder.with_plugin(p);
    }

    // CRIT-001 FIX: Resolve memory leak by scope-limited loader (ends with main)
    let mut loader = DynamicPluginLoader::new();
    if let Some(ref dir) = args.plugins_dir {
        match loader.load_plugins_from_dir(std::path::Path::new(dir)) {
            Ok(dynamic_plugins) => {
                for plugin in dynamic_plugins {
                    info!("Injecting dynamic plugin from {}: {}", dir, plugin.name());
                    builder = builder.with_plugin(plugin);
                }
            }
            Err(e) => {
                error!("⚠️ Failed to load dynamic plugins from {}: {}. Continuing without them.", dir, e);
            }
        }
    }

    let mut pipeline = builder.build()?;
    let target_hosts: Vec<TargetHost> = valid_targets.into_iter().map(|t| {
        let target_type = if t.contains("://") || t.contains('.') {
            redteam_rust_core::models::TargetType::Web
        } else if t.contains(':') && t.chars().filter(|&c| c == ':').count() > 1 {
            redteam_rust_core::models::TargetType::Network // IPv6
        } else if t.split('.').all(|s| s.parse::<u8>().is_ok()) && t.split('.').count() == 4 {
            redteam_rust_core::models::TargetType::Network // IPv4
        } else {
            redteam_rust_core::models::TargetType::Host
        };

        TargetHost {
            host: t,
            ip: None,
            status: TargetStatus::Pending,
            target_type,
            findings: Vec::new(),
            tool_suggestions: Vec::new(),
            tactical_context: serde_json::json!({}),
            extra_data: serde_json::json!({}),
        }
    }).collect();

    if args.autonomous {
        info!("🤖 SENTINEL: Activating Autonomous Agent with Native AI Cascade...");
        
        // Start standalone sink for Autonomous streaming
        let (sink_tx, sink_handle) = pipeline.start_sink_stage().await?;
        let pipeline_arc = Arc::new(pipeline);
        
        // Initialize Tiered AI Router (Native Cascade)
        let mut router = TieredAIRouter::new();
        
        // Tier 0: Local (Ollama) - Multi-model Redundancy
        let local_models = vec!["qwen2.5-coder:7b", "kimi-k2.5:cloud", "minimax-m2.5:cloud"];
        for model in local_models {
            router.add_client(RouteLevel::Local, Arc::new(OllamaClient::new(
                args.ollama_url.clone(),
                model.to_string()
            )?));
        }

        // Tier 1: Mid (Azure OpenAI) - Optimized for student credits
        if let (Ok(endpoint), Ok(key)) = (std::env::var("AZURE_OPENAI_ENDPOINT"), std::env::var("AZURE_OPENAI_KEY")) {
            info!("  - Mid Tier enabled (Azure OpenAI gpt-4o-mini)");
            router.add_client(RouteLevel::Mid, Arc::new(redteam_rust_core::core::agent::AzureOpenAIClient::new(
                endpoint,
                key,
                "gpt-4o-mini".to_string(),
                "2024-02-01".to_string()
            )?));
        }

        // Tier 2: Premium (Gemini) - Multi-key Redundancy
        if let Ok(keys_str) = std::env::var("GEMINI_API_KEYS") {
            let keys: Vec<String> = keys_str.split(',').map(|k| k.trim().to_string()).filter(|k| !k.is_empty()).collect();
            if !keys.is_empty() {
                info!("  - Premium Tier enabled with {} API keys", keys.len());
                router.add_client(RouteLevel::Premium, Arc::new(GeminiClient::new(
                    keys, 
                    "gemini-1.5-pro".to_string()
                )?));
            }
        } else if let Ok(key) = std::env::var("GEMINI_API_KEY") {
            // Fallback to single key if only GEMINI_API_KEY is present
            info!("  - Premium Tier enabled (Single Key)");
            router.add_client(RouteLevel::Premium, Arc::new(GeminiClient::new(
                vec![key], 
                "gemini-1.5-pro".to_string()
            )?));
        } else {
            warn!("  - Premium Tier DISABLED (GEMINI_API_KEYS/GEMINI_API_KEY not found). Fallback to Local/Mid tiers.");
        }

        let agent = redteam_rust_core::core::agent::AutonomousAgent::new(
            Arc::new(router),
            pipeline_arc,
            approval_gate
        );
        for target in target_hosts {
            if let Err(e) = agent.run_autopilot(target, sink_tx.clone()).await {
                error!("Autonomous agent failed on target: {}", e);
            }
        }
        drop(sink_tx);
        let _ = sink_handle.await;
    } else {
        if let Err(e) = pipeline.run(target_hosts).await {
            error!("Pipeline execution returned error: {}", e);
        }
    }

    
    // Generate HTML Report from JSONL stream
    let jsonl_path = args.jsonl_output.clone();
    if let Err(e) = redteam_rust_core::utils::generate_report(&jsonl_path, &args.html_output).await {
        error!("❌ Failed to generate HTML report: {}", e);
    } else {
         info!("✅ HTML Report saved to {}", args.html_output);
    }
    
    info!("✅ Scan complete. Incremental results saved to {}", jsonl_path);

    // --- INFRASTRUCTURE CLEANUP ---
    if let (Some(id), Some(client)) = (droplet_id, do_client) {
        info!("🧹 STEALTH CLEANUP: Destroying ephemeral infrastructure (ID: {})...", id);
        if let Err(e) = client.destroy_droplet(id).await {
            error!("❌ Failed to destroy droplet: {}. Please delete it manually in DO panel to avoid costs.", e);
        } else {
            info!("✅ Infrastructure destroyed successfully.");
        }
    }

    redteam_rust_core::utils::shutdown_telemetry();
    Ok(())
}
