use crate::core::blackarch::BlackArchTool;
use crate::core::resource_manager::SysResourceManager;
use crate::models::findings::Category;
use anyhow::{Result, Context};
use tokio::process::{Command, Child};
use tracing::{info, error};
#[cfg(unix)]


#[derive(Debug, PartialEq)]
pub enum ExecutionTier {
    StrictDocker, // Aislamiento Total en Contenedor Efímero
    FluidLocal,   // Fallback: Ejecución nativa con aislamiento PGID
}

pub struct SandboxDispatcher {
    pub(crate) res_mgr: SysResourceManager,
}

impl SandboxDispatcher {
    pub fn new(res_mgr: SysResourceManager) -> Self {
        Self { res_mgr }
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

    /// Ejecuta una herramienta devolviendo el objeto Child para permitir streaming de stdout/stderr.
    pub async fn execute_tool_streamed(&self, tool: &BlackArchTool, args: &[String]) -> Result<Child> {
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
            }
        }
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
