#![warn(clippy::all)]

use clap::Parser;
use redteam_rust_core::models::{TargetHost, TargetStatus};
use redteam_rust_core::plugins::net::NmapScanner;
use redteam_rust_core::plugins::osint::OsintScanner;
use redteam_rust_core::plugins::web::WebFuzzer;
use redteam_rust_core::core::plugin_loader::DynamicPluginLoader;
use redteam_rust_core::utils::LivenessChecker; 
use tracing::{info, error, warn};
// use std::collections::HashSet; // Removed
use regex::Regex;
use anyhow::{Context, Result};
use once_cell::sync::Lazy;
use tokio_util::sync::CancellationToken;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Target host to scan (e.g., google.com)
    #[arg(short, long)]
    target: Option<String>,

    /// Input file containing list of targets
    #[arg(short, long)]
    input: Option<String>,

    /// Output JSONL file path for scan results
    #[arg(short, long, default_value = "scan_result.jsonl")]
    jsonl_output: String,

    /// Output HTML report path
    #[arg(long, default_value = "scan_report.html")]
    html_output: String,

    /// Number of concurrent scans
    #[arg(short, long, default_value_t = 10)]
    concurrency: usize,

    /// Nmap Scripts to run (e.g., "default", "vuln", "http-title")
    #[arg(long)]
    scripts: Option<String>,

    /// Enable Stealth Mode (slower, T2 timing, lighter fingerprinting)
    #[arg(long, default_value_t = false)]
    stealth: bool,

    /// Enable Service Version Detection (-sV)
    #[arg(long, default_value_t = false)]
    service_detection: bool,

    /// Allow invalid TLS certificates (DANGEROUS)
    #[arg(long, default_value_t = false)]
    insecure: bool,

    /// Custom DNS servers (comma separated, e.g., "1.1.1.1,8.8.8.8")
    #[arg(long)]
    dns_servers: Option<String>,

    /// List of HTTP/S proxies (comma separated, e.g., "http://127.0.0.1:8080,http://proxy:3128")
    #[arg(long)]
    proxies: Option<String>,

    /// OpenTelemetry Collector Endpoint (e.g., "http://localhost:4317")
    #[arg(long)]
    otel_endpoint: Option<String>,

    /// Output logs in JSON format
    #[arg(long, default_value_t = false)]
    json_logs: bool,

    /// Optional directory to load compiled dynamic plugins (.so / .dylib)
    #[arg(long, value_name = "DIR")]
    plugins_dir: Option<String>,

    // --- Stealth Audit P1 & P2 ---

    /// Nmap Scan Type to use (e.g., sS, sA, sU). Degrades to TCP Connect without root.
    #[arg(long, default_value = "sS")]
    scan_type: String,

    /// Enable Nmap packet fragmentation (-f)
    #[arg(long, default_value_t = false)]
    fragment: bool,

    /// Nmap Decoys (-D), e.g., "1.1.1.1,8.8.8.8,ME"
    #[arg(long)]
    decoy: Option<String>,

    /// Enable DNS over HTTPS (DoH) for Liveness resolution (Privacy)
    #[arg(long, default_value_t = false)]
    doh: bool,

    /// Timeout for Nmap scans in seconds
    #[arg(long, default_value_t = 300)]
    nmap_timeout: u64,
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

    let args = Args::parse();
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
    let sink = Box::new(redteam_rust_core::core::JsonlSink::new(&args.jsonl_output).await?);

    let mut builder = redteam_rust_core::core::Pipeline::builder()
        .concurrency(args.concurrency)
        .shutdown_token(shutdown_token)
        .liveness_checker(liveness_checker.clone())
        .command_line(command_line)
        .with_sink(sink)
        .with_discovery(Box::new(OsintScanner::new()))
        .with_plugin(Box::new(WebFuzzer::new(
            args.insecure, 
            jitter.clone(),
            proxy_manager.clone()
        )))
        .with_plugin(Box::new(NmapScanner::new(
            args.scripts.clone(),
            args.stealth,
            args.service_detection,
            args.scan_type.clone(),
            args.fragment,
            args.decoy.clone(),
            args.nmap_timeout,
        )));

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

    let target_hosts = valid_targets.into_iter().map(|t| TargetHost {
        host: t,
        ip: None,
        status: TargetStatus::Pending,
        findings: Vec::new(),
    }).collect();

    if let Err(e) = pipeline.run(target_hosts).await {
        error!("Pipeline execution returned error: {}", e);
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
