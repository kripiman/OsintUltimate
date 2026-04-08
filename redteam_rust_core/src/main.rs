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
use redteam_rust_core::core::sandbox::SandboxDispatcher;
use redteam_rust_core::core::resource_manager::SysResourceManager;
use redteam_rust_core::core::factory::EngineFactory;

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
}

fn validate_target(target: &str) -> bool {
    if target.is_empty() || target.starts_with('-') {
        return false;
    }

    // 1. Valid as IP Address (v4 or v6)
    if target.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }

    // 2. Valid as URL
    if target.contains("://") {
        if let Ok(url) = url::Url::parse(target) {
            return url.host_str().is_some();
        }
    }

    // 3. Valid as Hostname
    static HOSTNAME_RE: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(|| {
        regex::Regex::new(r"^(?i)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$").unwrap()
    });
    HOSTNAME_RE.is_match(target)
}

fn is_ssrf_safe_host(host: &str) -> bool {
    if host.is_empty() { return false; }
    let host_lower = host.to_lowercase();
    
    // Exact name blacklist
    let name_blacklist = ["localhost", "broadcasthost", "local", "invalid"];
    if name_blacklist.iter().any(|&b| host_lower == b) {
        return false;
    }

    // Direct IP parse
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return match ip {
            std::net::IpAddr::V4(v4) => {
                let bytes = v4.octets();
                !(bytes[0] == 127 || bytes[0] == 10 || bytes[0] == 0 ||
                  (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) ||
                  (bytes[0] == 192 && bytes[1] == 168) ||
                  (bytes[0] == 169 && bytes[1] == 254) ||
                  (bytes[0] == 100 && (bytes[1] >= 64 && bytes[1] <= 127)) ||
                  (bytes[0] == 198 && (bytes[1] == 18 || bytes[1] == 19)) || // Benchmarking
                  (bytes[0] == 198 && bytes[1] == 51 && bytes[2] == 100) || // TEST-NET-2
                  (bytes[0] == 203 && bytes[1] == 0 && bytes[2] == 113) || // TEST-NET-3
                  (bytes[0] >= 240)) // Reserved
            },
            std::net::IpAddr::V6(v6) => {
                if v6.is_loopback() || v6.is_unspecified() { return false; }
                let segments = v6.segments();
                if (segments[0] & 0xffc0) == 0xfe80 { return false; } // Link Local
                if (segments[0] & 0xfe00) == 0xfc00 { return false; } // Unique Local
                if segments[0] == 0x2001 && segments[1] == 0x0db8 { return false; } // Doc
                if (segments[0] & 0xff00) == 0xff00 { return false; } // Multicast
                if segments[0] == 0x0100 && segments[1] == 0 && segments[2] == 0 && segments[3] == 0 { return false; } // Discard
                
                if let Some(v4) = v6.to_ipv4_mapped() {
                    return is_ssrf_safe_host(&v4.to_string());
                }
                true
            }
        };
    }

    // Decimal IP representation
    if host.chars().all(|c| c.is_digit(10)) {
        if let Ok(val) = host.parse::<u32>() {
            return is_ssrf_safe_host(&std::net::Ipv4Addr::from(val).to_string());
        }
    }

    // Octal/Hex checks could be more complex, but this covers major vectors
    true
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
    let (hw, auto_concurrency, soft_limit, hard_limit) = EngineFactory::detect_infrastructure_limits();
    info!("Hardware Detected: {:?} (Cores: {}, RAM: {}MB)", hw.infra_type, hw.cores, hw.ram_mb);

    // Auto-adjust concurrency based on HW if not specified by user or if default (10)
    if args.concurrency == 10 || args.concurrency > auto_concurrency {
        info!("Adjusting concurrency to {} based on detected hardware profile.", auto_concurrency);
        args.concurrency = auto_concurrency;
    }

    // Initialize Memory Monitor with dynamic limits
    let memory_monitor = Arc::new(redteam_rust_core::utils::MemoryMonitor::new(soft_limit as u32, hard_limit as u32));
    memory_monitor.start_logging();

    // --- MCP SERVER MODE ---
    if args.mcp_server {
        info!("🔮 [MCP-MODE] Activando servidor Model Context Protocol sobre SSE...");
        let jitter = std::sync::Arc::new(redteam_rust_core::utils::common::HumanJitter::new(100, 1500));
        let res_mgr = SysResourceManager::new();
        let sandbox = Arc::new(SandboxDispatcher::new(res_mgr));

        let config = redteam_rust_core::plugins::GlobalConfig {
            insecure: args.insecure,
            jitter: jitter.clone(),
            proxy_manager: None,
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
            sandbox: sandbox.clone(),
        };

        let server_mcp = redteam_rust_core::core::mcp::McpServer::new(config);
        server_mcp.run(args.mcp_port).await?;
        return Ok(());
    }

    // --- HYBRID SANDBOX INITIALIZATION ---
    let res_mgr = SysResourceManager::new();
    let sandbox = Arc::new(SandboxDispatcher::new(res_mgr));

    // 1. Determine Initial Targets (Stream Based)
    use futures::stream::StreamExt;
    let target_stream: futures::stream::BoxStream<'static, String> = if let Some(input_path) = args.input.clone() {
        use tokio::fs::File;
        use tokio::io::BufReader;
        let file = File::open(&input_path).await
            .with_context(|| format!("Failed to open input file: {}", input_path))?;
        let reader = BufReader::new(file);
        
        let s = tokio_stream::wrappers::LinesStream::new(tokio::io::AsyncBufReadExt::lines(reader))
            .filter_map(|res| async {
                match res {
                    Ok(line) if !line.trim().is_empty() => Some(line.trim().to_string()),
                    _ => None,
                }
            });
        Box::pin(s)
    } else if let Some(target) = args.target.clone() {
        Box::pin(futures::stream::iter(vec![target]))
    } else {
        anyhow::bail!("Either --target or --input must be provided.");
    };

    let mut target_hosts: futures::stream::BoxStream<'static, TargetHost> = target_stream
        .filter(|t| {
            let valid = validate_target(t);
            if !valid {
                error!("❌ Skipping invalid target: {}", t);
            }
            async move { valid }
        })
        .map(|t| {
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
                resolved_ip: None,
                status: TargetStatus::Pending,
                target_type,
                findings: Arc::new(Vec::new()),
                tool_suggestions: Arc::new(Vec::new()),
                tactical_context: Arc::new(serde_json::json!({})),
                extra_data: Arc::new(serde_json::json!({})),
            }
        })
        .boxed();

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
    if let Ok(c2_env) = std::env::var("C2_URL") {
        match url::Url::parse(&c2_env) {
            Ok(parsed_url) => {
                if parsed_url.scheme() != "https" {
                    anyhow::bail!("Security Violation: C2_URL must use HTTPS to prevent MitM leaks.");
                }
                
                let host = parsed_url.host_str().unwrap_or("");
                if !is_ssrf_safe_host(host) {
                     anyhow::bail!("Security Violation: C2_URL cannot point to internal/private addresses (SSRF prevention). Host rejected: {}", host);
                }

                let c2_token = std::env::var("C2_TOKEN").ok();
                info!("📡 C2 READY: Tactical Webhook exfiltration enabled to {}", parsed_url);
                multi_sink.add(Box::new(redteam_rust_core::core::sink::TacticalWebhookSink::new(parsed_url.to_string(), c2_token)?));
            }
            Err(e) => anyhow::bail!("Invalid C2_URL environment variable format: {}", e),
        }
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
        .memory_monitor(memory_monitor.clone())
        .sandbox(sandbox.clone());

    // Initialize Capability Layer Policy
    let max_layer = match args.max_layer.to_lowercase().as_str() {
        "passive" => redteam_rust_core::core::capability_layer::ScanLayer::Passive,
        "discovery" => redteam_rust_core::core::capability_layer::ScanLayer::Discovery,
        "scanning" => redteam_rust_core::core::capability_layer::ScanLayer::Scanning,
        "verification" => redteam_rust_core::core::capability_layer::ScanLayer::Verification,
        "exploitation" => redteam_rust_core::core::capability_layer::ScanLayer::Exploitation,
        "post-exploitation" | "post-exp" => redteam_rust_core::core::capability_layer::ScanLayer::PostExploitation,
        _ => {
            warn!("Invalid --max-layer '{}', defaulting to Scanning", args.max_layer);
            redteam_rust_core::core::capability_layer::ScanLayer::Scanning
        }
    };

    let policy = redteam_rust_core::core::capability_layer::ScanLayerPolicy {
        max_layer,
        require_approval_for_layer_3_plus: true, 
        require_approval_for_layer_4_plus: true,
        require_approval_for_layer_5: true,
    };
    
    let approval_gate = Arc::new(redteam_rust_core::core::approval_gate::ApprovalGate::for_red_team());
    
    builder = builder.policy(policy).approval_gate(approval_gate.clone());
    
    // --- DASHBOARD STARTUP ---
    if let Some(port) = args.dashboard {
        use redteam_rust_core::core::web_server::{DashboardState, DashboardAuth, generate_dashboard_token};
        use ed25519_dalek::SigningKey;
        use rand::RngCore;

        let (tx, targets) = (tokio::sync::broadcast::channel(1024).0, Arc::new(dashmap::DashMap::new()));
        builder = builder.with_dashboard(tx.clone(), targets.clone());
        
        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let mut session_id = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut session_id);
        
        let auth = Arc::new(DashboardAuth {
            verifying_key: signing_key.verifying_key(),
            session_id,
        });

        let token = generate_dashboard_token(&signing_key, session_id, 86400); // 24h expiry
        info!("🔑 [DASHBOARD-AUTH] Token de acceso (Bearer): {}", token);
        warn!("⚠️  Guarda este token. Lo necesitarás para autorizar decisiones críticas en el Dashboard (Header 'Authorization: Bearer <token>').");

        let dashboard_state = Arc::new(DashboardState {
            targets,
            findings_tx: tx,
            ram_limit_mb: hard_limit as u64,
            approval_gate: Some(approval_gate.clone()),
            budget: None,
            auth: auth.clone(),
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
        sandbox: sandbox.clone(),
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

    if args.swarm {
        let router = EngineFactory::build_default_router(args.ollama_url.clone())?;
        builder = builder.with_swarm(true, args.max_tokens, router);
    }

    let mut pipeline = builder.build()?;
    if args.autonomous {
        info!("🤖 SENTINEL: Activating Autonomous Agent with Native AI Cascade...");
        
        // Start standalone sink for Autonomous streaming
        let (sink_tx, sink_handle) = pipeline.start_sink_stage().await?;
        let pipeline_arc = Arc::new(pipeline);
        
        // Initialize AI Router (Native Cascade) via Factory
        let router = EngineFactory::build_default_router(args.ollama_url.clone())?;
        
        // Custom provider additions can still happen here if needed:
        if let Ok(key) = std::env::var("OPENAI_API_KEY") {
             // Example: Force O1-Preview for extra complex autonomous tasks
             info!("  - Special Tier: OpenAI (o1-preview) enabled");
        }

        let agent = redteam_rust_core::core::agent::AutonomousAgent::new(
            router,
            pipeline_arc,
            approval_gate
        );
        while let Some(target) = target_hosts.next().await {
            if let Err(e) = agent.run_autopilot(target, sink_tx.clone()).await {
                error!("Autonomous agent failed on target: {}", e);
            }
        }
        drop(sink_tx);
        let _ = sink_handle.await;
    } else if args.swarm {
        info!("🐝 SWARM: Multi-Agent Enjambre mode activated.");
        
        if let Err(e) = pipeline.run(target_hosts).await {
            error!("Swarm Pipeline execution error: {}", e);
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
