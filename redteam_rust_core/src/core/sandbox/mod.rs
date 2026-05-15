use crate::core::blackarch::BlackArchTool;
use crate::core::resource_manager::SysResourceManager;
use crate::models::findings::Category;
use anyhow::{Result, Context};
use tokio::process::{Command, Child};
use tracing::{info, error};
#[cfg(unix)]
pub mod wasm;


#[derive(Debug, PartialEq)]
pub enum ExecutionTier {
    StrictDocker, // Aislamiento Total en Contenedor Efímero
    FluidLocal,   // Fallback: Ejecución nativa con aislamiento PGID
    Wasm,         // [NEW] Aislamiento ligero vía wasmi
}

pub struct SandboxDispatcher {
    pub(crate) res_mgr: SysResourceManager,
    pub(crate) middleware: crate::core::middleware::MiddlewareRegistry,
    pub(crate) policy: Option<std::sync::Arc<dyn crate::core::policy::PolicyProvider>>,
    pub(crate) proxy_manager: Option<std::sync::Arc<crate::utils::proxy::ProxyManager>>,
    pub(crate) wasm_rt: wasm::WasmRuntime,
}

impl SandboxDispatcher {
    pub fn new(res_mgr: SysResourceManager) -> Self {
        Self { 
            res_mgr,
            middleware: crate::core::middleware::MiddlewareRegistry::default(),
            policy: None,
            proxy_manager: None,
            wasm_rt: wasm::WasmRuntime::new(),
        }
    }

    pub fn with_policy(mut self, policy: std::sync::Arc<dyn crate::core::policy::PolicyProvider>) -> Self {
        self.policy = Some(policy);
        self
    }

    pub fn with_proxy_manager(mut self, proxy_manager: std::sync::Arc<crate::utils::proxy::ProxyManager>) -> Self {
        self.proxy_manager = Some(proxy_manager);
        self
    }

    pub fn with_middleware(mut self, middleware: crate::core::middleware::MiddlewareRegistry) -> Self {
        self.middleware = middleware;
        self
    }

    pub fn determine_tier(&self, tool: &BlackArchTool) -> ExecutionTier {
        let category = self.map_blackarch_category(&tool.category);
        let is_exploit = matches!(category, Category::Vulnerability | Category::Windows | Category::Linux);
        
        if self.res_mgr.supports_strict_mode() {
            // Sistemas potentes (ej. 16GB, 32GB RAM): Todo en Docker (Sandbox total).
            ExecutionTier::StrictDocker
        } else {
            // Sistemas Fluidos (ej. 8GB RAM): Fallback activado.
            if is_exploit {
                // EXCEPCIÓN: Por seguridad, si es de penetración/explotación pura, forzamos Docker.
                info!("⚠️ [Sandbox] Tier Fluido activo, pero la herramienta '{}' es {:?}. Forzando sandbox StrictDocker por seguridad.", tool.name, category);
                ExecutionTier::StrictDocker
            } else {
                // Escáneres y OSINT: ejecutan nativo para ser fluidos de RAM.
                ExecutionTier::FluidLocal
            }
        }
    }

    fn map_blackarch_category(&self, cat: &str) -> Category {
        match cat.to_lowercase().as_str() {
            "exploitation" | "cracker" => Category::Vulnerability,
            "scanner" | "fuzzer" => Category::Scanning,
            "osint" | "recon" | "discovery" => Category::Recon,
            "webapp" => Category::SCA, // Map to SCA for webapp tools
            "windows" => Category::Windows,
            "linux" => Category::Linux,
            _ => Category::TechnologyStack,
        }
    }

    fn sanitize_args(&self, args: &[String]) -> Result<Vec<String>> {
        let mut sanitized = Vec::new();
        let forbidden_prefixes = ["--exec", "--script", "-e", "--eval", "--cmd"];
        let shell_metachars = [';', '|', '&', '$', '`', '(', ')', '{', '}', '<', '>', '\n', '\r'];

        for arg in args {
            if arg.is_empty() {
                anyhow::bail!("Empty argument not allowed");
            }

            // V14.4 HARDENING: Deep command safety check
            if let Some(reason) = self.check_command_safety(arg) {
                error!("Rejecting dangerous argument (Safety Check): {} - Reason: {}", arg, reason);
                anyhow::bail!("Dangerous command blocked: {}", reason);
            }

            for prefix in forbidden_prefixes {
                if arg.to_lowercase().starts_with(prefix) {
                    error!("Rejecting dangerous argument (prefix): {}", arg);
                    anyhow::bail!("Flag injection detected: {}", arg);
                }
            }

            for c in shell_metachars {
                if arg.contains(c) {
                    error!("Rejecting dangerous argument (metacharacter '{}'): {}", c, arg);
                    anyhow::bail!("Shell metacharacter detected in argument: {}", arg);
                }
            }

            if arg == ">" || arg == ">>" || arg == "<" {
                anyhow::bail!("Manual redirect not allowed in arguments");
            }

            sanitized.push(arg.clone());
        }
        Ok(sanitized)
    }

    const DANGEROUS_COMMANDS: &'static [(&'static str, &'static str)] = &[
        ("pkill",    "Use kill <pid> instead"),
        ("killall",  "Use kill <pid> instead"),
        ("nsenter",  "Container namespace escape blocked"),
        ("eval",     "Run the command directly instead"),
        ("iptables", "Firewall modification blocked — document persistence vector instead"),
        ("ip6tables","Firewall modification blocked"),
        ("nft",      "Firewall modification blocked"),
        ("rm",       "Destructive file removal blocked in sandbox"),
        ("base64",   "Potential payload decoding blocked if used as primary command"),
    ];

    const DANGEROUS_SUBCOMMANDS: &'static [(&'static str, &'static str, &'static str)] = &[
        ("docker", "exec",    "You are inside the sandbox — run commands directly"),
        ("docker", "run",     "You are inside the sandbox — run commands directly"),
        ("ip",     "route",   "Routing table modification blocked"),
        ("systemctl", "stop",  "Service termination blocked"),
        ("systemctl", "disable", "Service disabling blocked"),
    ];

    const DANGEROUS_TARGETS: &'static [&'static str] = &["bash", "tmux", "sh", "zsh", "python", "perl", "ruby"];

    /// Verifica si un comando o argumento es peligroso.
    /// Retorna Some(reason) si debe bloquearse, None si es seguro.
    pub fn check_command_safety(&self, cmd: &str) -> Option<String> {
        let tokens = self.tokenize_command(cmd);
        if tokens.is_empty() { return None; }

        let base_cmd = tokens[0].to_lowercase();
        
        // 1. Check direct commands
        for (dc, reason) in Self::DANGEROUS_COMMANDS {
            if base_cmd == *dc {
                return Some(reason.to_string());
            }
        }

        // 2. Check subcommands
        if tokens.len() > 1 {
            let subcommand = tokens[1].to_lowercase();
            for (dc, sub, reason) in Self::DANGEROUS_SUBCOMMANDS {
                if base_cmd == *dc && subcommand == *sub {
                    return Some(reason.to_string());
                }
            }
        }

        // 3. Check dangerous interactive targets
        for dt in Self::DANGEROUS_TARGETS {
            if base_cmd == *dt || tokens.iter().any(|t| t == *dt) {
                return Some(format!("Direct interactive shell calls ({}) are discouraged. Use specific tool commands.", dt));
            }
        }

        None
    }

    /// Tokeniza un comando shell de forma simple sin dependencias.
    /// Divide por espacios respetando comillas.
    fn tokenize_command(&self, cmd: &str) -> Vec<String> {
        let mut tokens = Vec::new();
        let mut current = String::new();
        let mut in_quotes = false;
        let mut quote_char = '\0';

        for c in cmd.chars() {
            if (c == '"' || c == '\'') && !in_quotes {
                in_quotes = true;
                quote_char = c;
            } else if c == quote_char && in_quotes {
                in_quotes = false;
            } else if c.is_whitespace() && !in_quotes {
                if !current.is_empty() {
                    tokens.push(current.clone());
                    current.clear();
                }
            } else {
                current.push(c);
            }
        }
        if !current.is_empty() {
            tokens.push(current);
        }
        tokens
    }

    /// Ejecuta una herramienta devolviendo el objeto Child para permitir streaming de stdout/stderr.
    pub async fn execute_tool_streamed(&self, tool: &BlackArchTool, args: &[String]) -> Result<Child> {
        // Phase 4: Run SafeCommandMiddlewares
        if let Some(policy) = &self.policy {
            self.middleware.validate_all(tool, args, policy.as_ref())?;
        } else {
            // Fallback for tools executed without a policy context (e.g. initial setup)
            // We still run basic sanitization which is already in execute_tool_streamed
        }

        let sanitized_args = self.sanitize_args(args)?;
        let tier = self.determine_tier(tool);
        let cost_mb = SysResourceManager::estimate_cost_mb(&tool.category);

        if !self.res_mgr.can_allocate(cost_mb) {
            anyhow::bail!("Backpressure: RAM insuficiente para '{}' ({} MB).", tool.name, cost_mb);
        }

        match tier {
            ExecutionTier::StrictDocker => {
                let category = self.map_blackarch_category(&tool.category);
                info!("🐳 [Sandbox-Stream] '{}' ({:?}) vía Docker. Límite: {}m", tool.name, category, cost_mb);
                
                let mut cmd = Command::new("docker");
                cmd.arg("run")
                   .arg("--rm")
                   .arg("-i") 
                   .arg(format!("--memory={}m", cost_mb))
                   .arg("--cap-drop=ALL") // Harden: drop all capabilities
                   .arg("--security-opt").arg("no-new-privileges") // Harden: no-new-privileges
                   .arg("--user").arg("1000:1000"); // Harden: run as non-root

                // Dynamic Networking Policy
                match category {
                    Category::Recon | Category::TechnologyStack => {
                        cmd.arg("--network=bridge"); // OSINT needs internet
                    },
                    Category::Scanning | Category::Vulnerability => {
                        // Some scanners need raw sockets (CAP_NET_RAW)
                        cmd.arg("--cap-add=NET_RAW"); 
                        cmd.arg("--network=bridge"); // REPLACED: host -> bridge for isolation
                    },
                    _ => {
                        cmd.arg("--network=none"); // Isolated by default
                    }
                }

                // F2-001 FIX: Inject ALL_PROXY if ProxyManager is active
                if let Some(ref pm) = self.proxy_manager {
                    if let Some(proxy_url) = pm.get_best_socks_url() {
                        cmd.arg(format!("--env=ALL_PROXY={}", proxy_url));
                        cmd.arg(format!("--env=all_proxy={}", proxy_url));
                        cmd.arg(format!("--env=HTTP_PROXY={}", proxy_url));
                        cmd.arg(format!("--env=HTTPS_PROXY={}", proxy_url));
                    }
                }

                cmd.arg("redteam-tools:v4-slim") 
                   .arg(&tool.name)
                   .args(sanitized_args)
                   .stdout(std::process::Stdio::piped())
                   .stderr(std::process::Stdio::piped());

                cmd.spawn().context("Fallo al spawnear Docker Sandbox")
            },
            ExecutionTier::FluidLocal => {
                info!("⚡ [Sandbox-Stream] '{}' Nativo (ProcessGuard).", tool.name);
                let mut cmd = Command::new(&tool.name);
                cmd.args(sanitized_args)
                   .stdout(std::process::Stdio::piped())
                   .stderr(std::process::Stdio::piped());

                #[cfg(unix)]
                unsafe {
                    cmd.pre_exec(|| {
                        if libc::setpgid(0, 0) == -1 {
                            return Err(std::io::Error::last_os_error());
                        }
                        Ok(())
                    });
                }
                cmd.spawn().context("Fallo al spawnear herramienta nativa")
            },
            ExecutionTier::Wasm => {
                anyhow::bail!("Wasm tier cannot be executed via streaming process (use execute_wasm instead)");
            }
        }
    }

    pub async fn execute_wasm(&self, wasm_bytes: &[u8], input_json: &str) -> Result<String> {
        self.wasm_rt.execute_plugin(wasm_bytes, input_json)
    }

    pub async fn execute_tool(&self, tool: &BlackArchTool, args: &[String]) -> Result<String> {
        let child = self.execute_tool_streamed(tool, args).await?;
        let output = child.wait_with_output().await.context("Error esperando salida del sandbox")?;
        
        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Error en sandbox tool '{}': {}", tool.name, err);
        }
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }
}
