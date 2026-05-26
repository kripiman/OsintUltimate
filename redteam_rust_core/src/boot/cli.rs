use clap::Parser;
use tracing::{info, warn};

#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    pub target: Option<String>,
    #[arg(long, help = "Path to local APK/IPA for mobile scanning")]
    pub apk: Option<String>,
    #[arg(long, help = "Container image reference (e.g. alpine:latest)")]
    pub image: Option<String>,
    #[arg(short, long)]
    pub input: Option<String>,
    #[arg(short, long, default_value = "scan_result.jsonl")]
    pub jsonl_output: String,
    #[arg(long, default_value = "scan_report.html")]
    pub html_output: String,
    #[arg(long)]
    pub postgres_url: Option<String>,
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
    #[arg(long, default_value_t = false, help = "Run as a distributed worker node")]
    pub worker: bool,
    #[arg(long, help = "Unique ID for this worker node")]
    pub node_id: Option<String>,
    #[arg(long, help = "NATS server URL for decentralized mesh")]
    pub nats_url: Option<String>,
    #[arg(long, help = "Scope ID for cross-target isolation and lateral movement grouping")]
    pub scope_id: Option<String>,
    #[arg(long, default_value = "scan", help = "Worker profile: scan, enrich, cve_correlation")]
    pub profile: String,
    #[arg(long, default_value_t = false, help = "Alias for --profile=cve_correlation (Box3 mode)")]
    pub cve_correlation_only: bool,
}

pub fn parse() -> Args {
    dotenv::dotenv().ok();
    let mut args = Args::parse();
    if std::env::args().len() <= 1 {
        // We use unwrap or default fallback here, since the original code exited if menu failed.
        // For simplicity and matching signature, we panic if menu fails as it's top-level boot.
        match crate::menu::show_menu() {
            Ok(Some(menu_args)) => args = menu_args,
            _ => {
                eprintln!("Operación cancelada por el usuario o configuración vacía.");
                std::process::exit(1);
            }
        }
    }
    args
}

pub async fn binary_health_check() {
    let p0_tools = vec!["bbscope", "asnmap", "cdncheck", "tlsx", "clairvoyance"];
    for tool in p0_tools {
        if !redteam_rust_core::utils::tool_detection::check_tool_availability(tool).await {
            warn!("🛡️ [PREFLIGHT] P0 TOOL MISSING: {}. Pipeline may be incomplete.", tool);
        } else {
            info!("🛡️ [PREFLIGHT] {} detected. OK.", tool);
        }
    }
}
