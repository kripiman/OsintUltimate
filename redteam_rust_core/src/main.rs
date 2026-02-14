use clap::Parser;
use redteam_rust_core::core::Orchestrator;
use redteam_rust_core::models::Finding;
use redteam_rust_core::plugins::net::NmapScanner;
use redteam_rust_core::plugins::osint::OsintScanner;
use redteam_rust_core::plugins::web::WebFuzzer;
use redteam_rust_core::utils::LivenessChecker; // Import
use tracing::{info, error, warn};
// use tracing_subscriber::FmtSubscriber; // Removed
use std::collections::HashSet;
use regex::Regex;
use futures::stream::{self, StreamExt}; // For concurrent liveness check
// use std::sync::Arc; // Removed

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Target host to scan (e.g., google.com)
    #[arg(short, long)]
    target: Option<String>,

    /// Input file containing list of targets
    #[arg(short, long)]
    input: Option<String>,

    /// Output JSON file path
    #[arg(short, long, default_value = "scan_result.json")]
    output: String,

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

    /// OpenTelemetry Collector Endpoint (e.g., "http://localhost:4317")
    #[arg(long)]
    otel_endpoint: Option<String>,

    /// Output logs in JSON format
    #[arg(long, default_value_t = false)]
    json_logs: bool,
}

fn validate_target(target: &str) -> bool {
    // Basic regex for Hostname (RFC 1123) or IP
    // Strict alphanumeric + dots + hyphens. No shell metachars.
    let re = Regex::new(r"^[a-zA-Z0-9.-]+$").unwrap();
    re.is_match(target) && !target.starts_with('-') // Prevent flag injection
}

use anyhow::{Context, Result}; // Add Result

#[tokio::main]
async fn main() -> Result<()> { 
    let args = Args::parse();

    // Initialize Telemetry (OTel or Standard)
    redteam_rust_core::utils::init_telemetry(args.otel_endpoint.clone(), args.json_logs)
        .context("Failed to initialize telemetry")?;

    // 1. Determine Initial Targets
    let initial_targets: Vec<String> = if let Some(input_path) = args.input.clone() {
        use std::fs::File;
        use std::io::{BufRead, BufReader};
        
        // Proper error handling for file operations
        let file = File::open(&input_path)
            .with_context(|| format!("Failed to open input file: {}", input_path))?;
        
        BufReader::new(file)
            .lines()
            .collect::<std::result::Result<Vec<_>, _>>() // Collect results first to catch errors
            .context("Failed to read lines from input file")?
            .into_iter()
            .filter(|l| !l.trim().is_empty())
            .collect()
    } else if let Some(target) = args.target.clone() {
        vec![target]
    } else {
        // We can still use eprintln and exit for usage errors, or return Err
        // Returning Err prints a nice error message with anyhow
        anyhow::bail!("Either --target or --input must be provided.");
    };

    // Validate Targets
    let valid_targets: Vec<String> = initial_targets.iter()
        .filter(|t| {
            if validate_target(t) {
                true
            } else {
                error!("❌ Skipping invalid target: {}", t);
                false
            }
        })
        .cloned()
        .collect();

    if valid_targets.is_empty() {
        anyhow::bail!("No valid targets found. Please check your input.");
    }

    // Parse DNS Servers
    let dns_servers: Option<Vec<String>> = args.dns_servers.as_ref().map(|s| {
        s.split(',')
            .map(|ip| ip.trim().to_string())
            .filter(|ip| !ip.is_empty())
            .collect()
    });

    // Initialize Shared LivenessChecker (holds DNS resolver)
    let liveness_checker = LivenessChecker::new(dns_servers);

    // --- PHASE 1: DISCOVERY (OSINT) ---
    info!("🔎 Starting Phase 1: Discovery (OSINT) on {} targets...", initial_targets.len());
    let discovery_orchestrator = Orchestrator::new(args.concurrency);
    discovery_orchestrator.register_plugin(Box::new(OsintScanner::new(liveness_checker.clone()))).await;

    // Run Discovery Phase
    let discovery_result = discovery_orchestrator.run(valid_targets.clone()).await;

    // Extract Discovered Subdomains
    // We use a HashSet to avoid duplicates
    let mut all_targets_set: HashSet<String> = valid_targets.into_iter().collect();
    let mut discovered_subdomains: HashSet<String> = HashSet::new();

    for target in &discovery_result.targets {
        for finding in &target.findings {
            if finding.id == "SUBDOMAIN-DISCOVERY" {
                // The evidence json has "subdomain" field
                if let Some(subdomain) = finding.evidence.data.get("subdomain").and_then(|v| v.as_str()) {
                    if !all_targets_set.contains(subdomain) {
                         discovered_subdomains.insert(subdomain.to_string());
                         all_targets_set.insert(subdomain.to_string());
                    }
                }
            }
        }
    }

    info!("✨ Discovery Complete. Found {} new subdomains.", discovered_subdomains.len());
    if !discovered_subdomains.is_empty() {
        info!("Sample subdomains: {:?}", discovered_subdomains.iter().take(3).collect::<Vec<_>>());
    }

    let all_targets_pre_check: Vec<String> = all_targets_set.into_iter().collect();
    let all_targets_pre_check_len = all_targets_pre_check.len();

    // --- PHASE 1.5: LIVENESS VERIFICATION ---
    info!("💓 Verifying liveness of {} targets before deep scan...", all_targets_pre_check_len);
    
    // Concurrent Liveness Check
    let valid_targets_stream = stream::iter(all_targets_pre_check)
        .map(|target| {
            let checker = liveness_checker.clone();
            async move {
                if let Some(_ip) = checker.is_live(&target).await {
                    Some(target)
                } else {
                    None
                }
            }
        })
        .buffer_unordered(args.concurrency * 2); // Higher concurrency for DNS

    let live_targets: Vec<String> = valid_targets_stream
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .flatten()
        .collect();

    if live_targets.is_empty() {
        anyhow::bail!("All targets failed liveness check (DNS resolution). Aborting scan.");
    }

    let dropped_count = all_targets_pre_check_len - live_targets.len();
    if dropped_count > 0 {
        warn!("⚠️ Dropped {} dead targets. Proceeding with {} live targets.", dropped_count, live_targets.len());
    } else {
        info!("✅ All targets are live.");
    }

    // --- PHASE 2: SCANNING (Nmap + Web) ---
    info!("🚀 Starting Phase 2: Scanning (Nmap + Web) on {} total targets...", live_targets.len());
    
    // We create a new orchestrator for the scanning phase
    let scanning_orchestrator = Orchestrator::new(args.concurrency);
    
    // Register active scanners
    scanning_orchestrator.register_plugin(Box::new(WebFuzzer::new(args.insecure))).await;
    scanning_orchestrator.register_plugin(Box::new(NmapScanner::new(
        args.scripts.clone(),
        args.stealth,
        args.service_detection
    ))).await;

    // Run Scan on ALL targets (including subdomains)
    let mut final_scan_result = scanning_orchestrator.run(live_targets).await;

    // --- MERGE RESULTS ---
    // We need to merge the OSINT findings back into the final result for the original targets.
    // The `final_scan_result` contains the Nmap/Web results for everyone.
    // The `discovery_result` contains OSINT results for original targets.

    info!("🔄 Merging Discovery findings into Final Report...");
    
    // Create a map of host -> findings from discovery for faster lookup
    let mut discovery_findings_map: std::collections::HashMap<String, Vec<Finding>> = std::collections::HashMap::new();
    for target in discovery_result.targets {
        if !target.findings.is_empty() {
            discovery_findings_map.insert(target.host, target.findings);
        }
    }

    for final_target in &mut final_scan_result.targets {
        if let Some(findings) = discovery_findings_map.remove(&final_target.host) {
            final_target.findings.extend(findings);
        }
    }

    // Export Result
    let json = serde_json::to_string_pretty(&final_scan_result)
        .context("Failed to serialize results to JSON")?;
        
    std::fs::write(&args.output, json)
        .with_context(|| format!("Unable to write result file: {}", args.output))?;
    
    // Generate HTML Report
    if let Err(e) = redteam_rust_core::utils::generate_report(&final_scan_result, &args.html_output) {
        error!("❌ Failed to generate HTML report: {}", e);
        // We don't fail the whole run if reporting fails, just log it.
    } else {
         info!("✅ HTML Report saved to {}", args.html_output);
    }
    
    info!("✅ Scan complete. Results saved to {}", args.output);
    
    // Ensure traces are flushed
    redteam_rust_core::utils::shutdown_telemetry();
    
    Ok(())
}
