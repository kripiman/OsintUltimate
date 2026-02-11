use clap::Parser;
use redteam_rust_core::core::Orchestrator;
use redteam_rust_core::plugins::net::NmapScanner;
use redteam_rust_core::plugins::osint::OsintScanner;
use redteam_rust_core::plugins::web::WebFuzzer;
use tracing_subscriber::FmtSubscriber;

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
}

#[tokio::main]
async fn main() {
    // Initialize logging with explicit filter
    // Default to INFO, but allow RUST_LOG env var to override
    let subscriber = FmtSubscriber::builder()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "redteam_rust_core=info".into()),
        )
        .with_target(false) // Clean output
        .with_thread_ids(true)
        .finish();
        
    tracing::subscriber::set_global_default(subscriber)
        .expect("setting default subscriber failed");

    let args = Args::parse();

    // Determine Targets
    let targets: Vec<String> = if let Some(input_path) = args.input {
        use std::fs::File;
        use std::io::{BufRead, BufReader};
        
        let file = File::open(&input_path)
            .unwrap_or_else(|_| panic!("Failed to open input file: {}", input_path));
        
        BufReader::new(file)
            .lines()
            .map(|l| l.expect("Failed to read line"))
            .filter(|l| !l.trim().is_empty())
            .collect()
    } else if let Some(target) = args.target {
        vec![target]
    } else {
        eprintln!("Error: Either --target or --input must be provided.");
        std::process::exit(1);
    };

    // Initialize Orchestrator
    let orchestrator = Orchestrator::new(args.concurrency);
    
    // Register Plugins
    orchestrator.register_plugin(Box::new(WebFuzzer::new())).await;
    orchestrator.register_plugin(Box::new(NmapScanner::new(
        args.scripts,
        args.stealth,
        args.service_detection
    ))).await;
    orchestrator.register_plugin(Box::new(OsintScanner::new())).await;

    // Run Scan
    println!("🚀 Starting RedTeam Rust Engine...");
    let result = orchestrator.run(targets).await;

    // Export Result
    let json = serde_json::to_string_pretty(&result).unwrap();
    std::fs::write(&args.output, json).expect("Unable to write file");
    
    // Generate HTML Report
    if let Err(e) = redteam_rust_core::utils::generate_report(&result, &args.html_output) {
        println!("❌ Failed to generate HTML report: {}", e);
    } else {
         println!("✅ HTML Report saved to {}", args.html_output);
    }
    
    println!("✅ Scan complete. Results saved to {}", args.output);
}
