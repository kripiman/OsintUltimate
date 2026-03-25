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

    // 1. Determine Initial Targets
    let initial_targets: Vec<String> = if let Some(input_path) = args.input.clone() {
        use std::fs::File;
        use std::io::{BufRead, BufReader};
        let file = File::open(&input_path)
            .with_context(|| format!("Failed to open input file: {}", input_path))?;
        BufReader::new(file)
            .lines()
            .collect::<std::result::Result<Vec<_>, _>>()?
            .into_iter()
            .filter(|l| !l.trim().is_empty())
            .collect()
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
    static SCAN_TYPE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^s[STAUYNFXW]$").unwrap());
    if !SCAN_TYPE_RE.is_match(&args.scan_type) {
        anyhow::bail!("Invalid --scan-type parameter. Must be a valid Nmap scan type (e.g., sS, sT, sU, sA).");
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
    let proxy_manager = args.proxies.as_ref().map(|s| {
        let proxies_list = s.split(',').map(|p| p.trim().to_string()).filter(|p| !p.is_empty()).collect();
        std::sync::Arc::new(redteam_rust_core::utils::proxy::ProxyManager::new(proxies_list, args.insecure))
    });

    // Global Shutdown Token (CancellationToken is better than broadcast for hierarchies)
    let shutdown_token = CancellationToken::new();
    
    let shutdown_token_clone = shutdown_token.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        warn!("🛑 Graceful shutdown initiated. Cleaning up...");
        shutdown_token_clone.cancel();
    });

    // --- PIPELINE SETUP ---
    let sink: Box<dyn redteam_rust_core::core::DataSink> = if let Some(ref db_path) = args.sqlite_output {
        info!("🗄️ Using SQLite persistence at {}", db_path);
        Box::new(redteam_rust_core::core::SqliteSink::new(db_path).await?)
    } else {
        Box::new(redteam_rust_core::core::JsonlSink::new(&args.jsonl_output).await?)
    };

    let mut builder = redteam_rust_core::core::Pipeline::builder()
        .concurrency(args.concurrency)
        .shutdown_token(shutdown_token)
        .liveness_checker(liveness_checker.clone())
        .command_line(command_line)
        .with_sink(sink);

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
        let dynamic_plugins = loader.load_plugins_from_dir(std::path::Path::new(dir))?;
        for plugin in dynamic_plugins {
            info!("Injecting dynamic plugin from {}: {}", dir, plugin.name());
            builder = builder.with_plugin(plugin);
        }
    }

    let pipeline = builder.build()?;
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
            extra_data: serde_json::json!({}),
        }
    }).collect();

    if args.autonomous {
        info!("🤖 SENTINEL: Activating Autonomous Agent with Native AI Cascade...");
        let pipeline_arc = Arc::new(pipeline);
        
        // Initialize Tiered AI Router (Native Cascade)
        let mut router = TieredAIRouter::new();
        
        // Tier 0: Local (Ollama)
        router.add_client(RouteLevel::Local, Arc::new(OllamaClient::new(
            args.ollama_url.clone(),
            "qwen2.5-coder:7b".to_string()
        )));

        // Tier 2: Premium (Gemini) - Requires GEMINI_API_KEY in .env
        if let Ok(key) = std::env::var("GEMINI_API_KEY") {
            info!("  - Premium Tier enabled (Gemini 1.5 Pro)");
            router.add_client(RouteLevel::Premium, Arc::new(GeminiClient::new(
                key, 
                "gemini-1.5-pro".to_string()
            )));
        } else {
            warn!("  - Premium Tier DISABLED (GEMINI_API_KEY not found). All tasks will default to Local tier.");
        }

        let agent = redteam_rust_core::core::agent::AutonomousAgent::new(
            Arc::new(router),
            pipeline_arc,
            approval_gate
        );
        for target in target_hosts {
            if let Err(e) = agent.run_autopilot(target).await {
                error!("Autonomous agent failed on target: {}", e);
            }
        }
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
    redteam_rust_core::utils::shutdown_telemetry();
    Ok(())
}
