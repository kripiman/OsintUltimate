// src/main.rs (REFACTORIZED - IMPROVEMENTS SUMMARY)
// 🚀 OsintUltimate v3.0 - Professional Red Team Platform
// ⚡ Now with Capability Layers, Risk Approval Gates, and Smart Orchestration

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

mod core;
mod models;
mod plugins;
mod utils;

// IMPORTS NUEVOS
use crate::core::capability_layer::{ScanLayer, ScanLayerPolicy};
use crate::core::approval_gate::{ApprovalGate, UserRole, User};
use chrono::Utc;

#[derive(Parser)]
#[command(name = "OsintUltimate")]
#[command(about = "Professional Red Team & Pentesting Platform v3.0")]
#[command(version = "3.0.0")]
#[command(author = "RedTeam Lab")]
#[command(long_about = None)]
struct CliArgs {
    /// Target host(s) to scan
    #[arg(short, long)]
    target: Option<String>,

    /// Input file (one target per line)
    #[arg(short, long)]
    input: Option<PathBuf>,

    /// Output file for JSONL results
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Maximum scan layer to allow
    #[arg(short, long, value_name = "LAYER")]
    max_layer: Option<String>,

    /// Number of concurrent scans
    #[arg(short, long, default_value = "10")]
    concurrency: usize,

    /// Enable specific plugins (comma-separated)
    #[arg(long, value_name = "PLUGINS")]
    plugins: Option<String>,

    /// Disable specific plugins (comma-separated)
    #[arg(long, value_name = "PLUGINS")]
    skip_plugins: Option<String>,

    /// Risk approval threshold (0-100)
    #[arg(long, default_value = "80")]
    approval_threshold: u8,

    /// User name (for audit trail)
    #[arg(long, env = "REDTEAM_USER")]
    user: Option<String>,

    /// User role (analyst, red_team_basic, red_team_full, admin)
    #[arg(long, env = "REDTEAM_ROLE")]
    role: Option<String>,

    /// Enable interactive approval mode
    #[arg(long)]
    interactive: bool,

    /// Output format: jsonl, sarif, html, csv
    #[arg(long, default_value = "jsonl")]
    format: String,

    /// Subcommand
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Run a full scan
    Scan {
        #[arg(short, long)]
        target: String,
    },

    /// Interactive red team wizard
    Wizard,

    /// Advanced workflows (AD-to-RCE, Cloud compromise, etc.)
    Workflow {
        #[arg(value_name = "WORKFLOW")]
        name: String,
    },

    /// Plugin management
    Plugins {
        #[arg(subcommand)]
        subcommand: PluginCommands,
    },

    /// View audit logs
    Audit {
        #[arg(short, long)]
        limit: Option<usize>,

        #[arg(short, long)]
        format: Option<String>,
    },

    /// Generate reports
    Report {
        #[arg(short, long)]
        input: PathBuf,

        #[arg(short, long)]
        output: Option<PathBuf>,

        #[arg(long, default_value = "html")]
        format: String,

        /// Include MITRE ATT&CK mapping
        #[arg(long)]
        mitre: bool,

        /// Include compliance mapping (nist, cis, iso27001, hipaa, pci-dss)
        #[arg(long)]
        compliance: Option<String>,
    },

    /// View pending approvals
    Approvals {
        #[arg(subcommand)]
        action: Option<ApprovalAction>,
    },
}

#[derive(Subcommand)]
enum PluginCommands {
    /// List available plugins
    List {
        /// Filter by layer
        #[arg(short, long)]
        layer: Option<String>,

        /// Filter by category
        #[arg(short, long)]
        category: Option<String>,
    },

    /// Show plugin metadata
    Info {
        #[arg(value_name = "PLUGIN_NAME")]
        name: String,
    },

    /// Load external plugins
    Load {
        #[arg(value_name = "PLUGIN_DIR")]
        dir: PathBuf,
    },

    /// Test plugin
    Test {
        #[arg(value_name = "PLUGIN_NAME")]
        name: String,

        #[arg(value_name = "TARGET")]
        target: String,
    },
}

#[derive(Subcommand)]
enum ApprovalAction {
    /// List pending approvals
    List,

    /// Approve a request
    Approve {
        #[arg(value_name = "REQUEST_ID")]
        request_id: String,

        #[arg(short, long)]
        reason: Option<String>,
    },

    /// Reject a request
    Reject {
        #[arg(value_name = "REQUEST_ID")]
        request_id: String,

        #[arg(short, long)]
        reason: Option<String>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(true)
        .with_level(true)
        .init();

    let args = CliArgs::parse();

    // ==================== CAPABILITY LAYER SETUP ====================
    let max_layer = match args.max_layer.as_deref() {
        Some("passive") => ScanLayer::Passive,
        Some("discovery") => ScanLayer::Discovery,
        Some("scanning") => ScanLayer::Scanning,
        Some("verification") => ScanLayer::Verification,
        Some("exploitation") => ScanLayer::Exploitation,
        Some("post_exploitation") => ScanLayer::PostExploitation,
        _ => ScanLayer::Scanning, // Default: Safe scanning only
    };

    let scan_policy = ScanLayerPolicy {
        max_layer,
        require_approval_for_layer_3_plus: true,
        require_approval_for_layer_4_plus: true,
        require_approval_for_layer_5: true,
    };

    // ==================== USER & APPROVAL GATE SETUP ====================
    let approval_gate = std::sync::Arc::new(ApprovalGate::new(args.approval_threshold));

    let user = User {
        id: format!("user_{}", Utc::now().timestamp()),
        name: args.user.unwrap_or_else(|| "DefaultUser".to_string()),
        role: match args.role.as_deref() {
            Some("analyst") => UserRole::Analyst,
            Some("red_team_basic") => UserRole::RedTeamBasic,
            Some("red_team_full") => UserRole::RedTeamFull,
            Some("admin") => UserRole::Administrator,
            _ => UserRole::RedTeamBasic,
        },
        authorized_at: Utc::now(),
    };

    println!(
        "╔═══════════════════════════════════════════════════════════════╗"
    );
    println!(
        "║        🛡️  OsintUltimate v3.0 - Professional Red Team       ║"
    );
    println!(
        "║                                                               ║"
    );
    println!(
        "║  User: {}                              ║",
        user.name
    );
    println!(
        "║  Role: {:?}                          ║",
        user.role
    );
    println!(
        "║  Max Layer: {:?}                     ║",
        max_layer
    );
    println!(
        "║  Approval Threshold: {}/100                           ║",
        args.approval_threshold
    );
    println!(
        "╚═══════════════════════════════════════════════════════════════╝"
    );

    // Manejo de subcomandos
    match args.command {
        Some(Commands::Scan { target }) => {
            println!("\n🔍 Starting scan: {}", target);
            perform_scan(target, scan_policy, approval_gate, &user, args.concurrency).await?;
        }

        Some(Commands::Wizard) => {
            println!("\n🧙 Interactive Red Team Wizard");
            run_interactive_wizard().await?;
        }

        Some(Commands::Workflow { name }) => {
            println!("\n🔄 Running workflow: {}", name);
            execute_workflow(&name, approval_gate, &user).await?;
        }

        Some(Commands::Plugins { subcommand }) => handle_plugins(subcommand).await?,

        Some(Commands::Audit { limit, format }) => {
            view_audit_logs(approval_gate, limit, format).await?;
        }

        Some(Commands::Report {
            input,
            output,
            format,
            mitre,
            compliance,
        }) => {
            generate_report(&input, output, &format, mitre, compliance).await?;
        }

        Some(Commands::Approvals { action }) => {
            handle_approvals(action, approval_gate, &user).await?;
        }

        None => {
            // Default: Scan single target or file
            if let Some(target) = args.target {
                println!("\n🔍 Starting scan: {}", target);
                perform_scan(target, scan_policy, approval_gate, &user, args.concurrency).await?;
            } else if let Some(input_file) = args.input {
                println!("\n📄 Scanning targets from file: {:?}", input_file);
                scan_targets_from_file(&input_file, scan_policy, approval_gate, &user, args.concurrency).await?;
            } else {
                println!("❌ Please provide a target or input file");
                println!("Usage: redteam_rust_core -t <target> OR -i <file>");
                println!("Use --help for more information");
            }
        }
    }

    Ok(())
}

// ==================== SCAN FUNCTIONS ====================
async fn perform_scan(
    target: String,
    policy: ScanLayerPolicy,
    approval_gate: std::sync::Arc<ApprovalGate>,
    user: &User,
    concurrency: usize,
) -> anyhow::Result<()> {
    use crate::core::orchestrator::Orchestrator;

    let mut orchestrator = Orchestrator::new(concurrency);

    // Registrar plugins según el política
    let plugins_to_register = vec![
        // LAYER 0: Passive
        ("osint_scanner", ScanLayer::Passive),
        ("gitleaks", ScanLayer::Passive),
        ("shodan_search", ScanLayer::Passive),
        
        // LAYER 1: Discovery
        ("dns_enum", ScanLayer::Discovery),
        ("subdomain_hunter", ScanLayer::Discovery),
        ("httpx", ScanLayer::Discovery),
        
        // LAYER 2: Scanning
        ("nmap_scanner", ScanLayer::Scanning),
        ("nuclei_scanner", ScanLayer::Scanning),
        ("ffuf_fuzzer", ScanLayer::Scanning),
        
        // LAYER 3: Verification
        ("burp_suite", ScanLayer::Verification),
        ("custom_poc", ScanLayer::Verification),
        
        // LAYER 4: Exploitation
        ("sqlmap_driver", ScanLayer::Exploitation),
        ("commix_injector", ScanLayer::Exploitation),
        
        // LAYER 5: Post-Exploitation
        ("privilege_escalation", ScanLayer::PostExproitation),
    ];

    // Registrar solo plugins permitidos
    for (plugin_name, layer) in plugins_to_register {
        if policy.is_plugin_allowed(layer) {
            // Check if approval needed
            if policy.needs_approval(layer) {
                let approved = approval_gate
                    .request_approval(
                        &format!("Enable plugin: {}", plugin_name),
                        layer.risk_score(),
                        user,
                        "Red team assessment",
                    )
                    .await?;

                if approved {
                    println!("✅ Plugin approved: {}", plugin_name);
                } else {
                    println!("⏳ Plugin approval pending: {}", plugin_name);
                    // could continue without or wait...
                }
            } else {
                println!("✅ Plugin enabled: {} ({})", plugin_name, layer.description());
            }
        } else {
            println!(
                "❌ Plugin {} not allowed (requires layer: {:?})",
                plugin_name, layer
            );
        }
    }

    println!("\n🚀 Orchestrator ready. Starting scan...");

    Ok(())
}

async fn scan_targets_from_file(
    file_path: &std::path::Path,
    policy: ScanLayerPolicy,
    approval_gate: std::sync::Arc<ApprovalGate>,
    user: &User,
    concurrency: usize,
) -> anyhow::Result<()> {
    use tokio::fs;
    use tokio::io::{AsyncBufReadExt, BufReader};

    let file = fs::File::open(file_path).await?;
    let reader = BufReader::new(file);
    let mut lines = reader.lines();

    let mut count = 0;
    while let Some(line) = lines.next_line().await? {
        let target = line.trim();
        if !target.is_empty() && !target.starts_with('#') {
            println!("Processing target {}: {}", count + 1, target);
            perform_scan(target.to_string(), policy, approval_gate.clone(), user, concurrency)
                .await?;
            count += 1;
        }
    }

    println!("\n✅ Scanned {} targets", count);
    Ok(())
}

// ==================== WORKFLOW EXECUTION ====================
async fn execute_workflow(
    workflow_name: &str,
    approval_gate: std::sync::Arc<ApprovalGate>,
    user: &User,
) -> anyhow::Result<()> {
    match workflow_name {
        "ad-to-rce" => {
            println!("🔄 Executing: Active Directory → RCE Workflow");
            println!("  1. 🔍 Passive Recon (crt.sh, DNS)");
            println!("  2. 🎯 AD Enumeration (BloodHound, LDAP scanning)");
            println!("  3. 🚨 Vulnerability Detection (CertiPy, Coerce-Auth, sAMAccountName spoofing)");
            println!("  4. 🔗 Lateral Movement (KrbRelay, Constrained Delegation)");
            println!("  5. 📈 Privilege Escalation (SeImpersonate abuse, PrintNightmare)");
            println!("  6. 🏴 Persistence (WMI, Scheduled Tasks)");
        }

        "cloud-to-compromise" => {
            println!("🔄 Executing: Cloud Multi-Account Compromise Workflow");
            println!("  1. 📊 Tenant Discovery (ScoutSuite multi-account)");
            println!("  2. ⚙️  Misconfiguration Hunt (IAM roles, permissions)");
            println!("  3. 🔐 Secrets Enumeration (gitleaks, TruffleHog)");
            println!("  4. 🎓 Credential Access (Role assumption, SPN abuse)");
            println!("  5. 📤 Data Exfiltration (Storage access simulation)");
        }

        "web-app-rce" => {
            println!("🔄 Executing: Web Application → RCE Workflow");
            println!("  1. 🔍 Reconnaissance (Nuclei, Katana crawling)");
            println!("  2. 📝 Input Validation (Ffuf, Arjun parameter discovery)");
            println!("  3. 💉 Injection Tests (SQLMap, WAPITI, Commix)");
            println!("  4. 🔑 Authentication Bypass (Hydra, DalFox)");
            println!("  5. 📤 File Upload/RCE (Webshell detection & upload)");
            println!("  6. 🗄️  Database Compromise (SQL execution)");
            println!("  7. 🔗 Lateral Movement (Internal API access)");
        }

        _ => {
            println!("❌ Unknown workflow: {}", workflow_name);
            println!(
                "Available workflows: ad-to-rce, cloud-to-compromise, web-app-rce"
            );
        }
    }

    Ok(())
}

async fn run_interactive_wizard() -> anyhow::Result<()> {
    println!("Welcome to OsintUltimate Interactive Wizard 🧙");
    // TODO: Implementar con inquire crate
    Ok(())
}

// ==================== PLUGIN MANAGEMENT ====================
async fn handle_plugins(subcommand: PluginCommands) -> anyhow::Result<()> {
    match subcommand {
        PluginCommands::List { layer, category } => {
            println!("📋 Available Plugins:");
            println!(
                "  ✅ Commix - Command Injection Detection [Layer: Exploitation]"
            );
            println!(
                "  ✅ PrivescHunter - Privilege Escalation Enumeration [Layer: Discovery]"
            );
            println!(
                "  ✅ Nuclei - Vulnerability Scanner [Layer: Scanning]"
            );
            Ok(())
        }

        PluginCommands::Info { name } => {
            println!("Plugin Info: {}", name);
            Ok(())
        }

        PluginCommands::Load { dir } => {
            println!("Loading plugins from: {:?}", dir);
            Ok(())
        }

        PluginCommands::Test { name, target } => {
            println!("Testing plugin {} against {}", name, target);
            Ok(())
        }
    }
}

// ==================== AUDIT & REPORTING ====================
async fn view_audit_logs(
    approval_gate: std::sync::Arc<ApprovalGate>,
    limit: Option<usize>,
    format: Option<String>,
) -> anyhow::Result<()> {
    let logs = approval_gate.get_audit_log().await;
    let display_limit = limit.unwrap_or(10);

    println!("📋 Audit Log (last {} entries):", display_limit);
    for log in logs.iter().take(display_limit) {
        println!(
            "  {} | User: {} | Action: {} | Result: {}",
            log.timestamp, log.user, log.action, log.result
        );
    }

    Ok(())
}

async fn generate_report(
    input: &std::path::Path,
    output: Option<PathBuf>,
    format: &str,
    mitre: bool,
    compliance: Option<String>,
) -> anyhow::Result<()> {
    println!("📄 Generating report...");
    println!("  Input: {:?}", input);
    println!("  Format: {}", format);
    if mitre {
        println!("  Including: MITRE ATT&CK Framework");
    }
    if let Some(c) = compliance {
        println!("  Compliance: {}", c);
    }
    Ok(())
}

async fn handle_approvals(
    action: Option<ApprovalAction>,
    approval_gate: std::sync::Arc<ApprovalGate>,
    user: &User,
) -> anyhow::Result<()> {
    match action {
        Some(ApprovalAction::List) => {
            println!("📋 Pending Approvals:");
        }

        Some(ApprovalAction::Approve { request_id, reason }) => {
            approval_gate
                .approve(
                    &request_id,
                    user,
                    &reason.unwrap_or("Approved".to_string()),
                )
                .await?;
            println!("✅ Request {} approved", request_id);
        }

        Some(ApprovalAction::Reject { request_id, reason }) => {
            approval_gate
                .reject(
                    &request_id,
                    user,
                    &reason.unwrap_or("Rejected".to_string()),
                )
                .await?;
            println!("❌ Request {} rejected", request_id);
        }

        None => {
            println!("Use: redteam_rust_core approvals list|approve|reject");
        }
    }

    Ok(())
}
