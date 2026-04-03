use crate::core::blackarch::BlackArchTool;
use crate::core::resource_manager::SysResourceManager;
use anyhow::{Result, Context};
use tokio::process::{Command, Child};
use tracing::{info, warn, error};
use std::os::unix::process::CommandExt;

#[derive(Debug, PartialEq)]
pub enum ExecutionTier {
    StrictDocker, // Aislamiento Total en Contenedor Efímero
    FluidLocal,   // Fallback: Ejecución nativa con aislamiento PGID
}

pub struct SandboxDispatcher {
    pub res_mgr: SysResourceManager,
}

impl SandboxDispatcher {
    pub fn new(res_mgr: SysResourceManager) -> Self {
        Self { res_mgr }
    }

    pub fn determine_tier(&self, tool: &BlackArchTool) -> ExecutionTier {
        let is_exploit = tool.category.to_lowercase() == "exploitation";
        
        if self.res_mgr.supports_strict_mode() {
            // Sistemas potentes (ej. 16GB, 32GB RAM): Todo en Docker (Sandbox total).
            ExecutionTier::StrictDocker
        } else {
            // Sistemas Fluidos (ej. 8GB RAM): Fallback activado.
            if is_exploit {
                // EXCEPCIÓN: Por seguridad, si es de penetración/explotación pura, forzamos Docker.
                info!("⚠️ [Sandbox] Tier Fluido activo, pero la herramienta '{}' es EXPLOITATION. Forzando sandbox StrictDocker por seguridad.", tool.name);
                ExecutionTier::StrictDocker
            } else {
                // Escáneres y OSINT: ejecutan nativo para ser fluidos de RAM.
                ExecutionTier::FluidLocal
            }
        }
    }

    /// Ejecuta una herramienta devolviendo el objeto Child para permitir streaming de stdout/stderr.
    pub async fn execute_tool_streamed(&self, tool: &BlackArchTool, args: &[String]) -> Result<Child> {
        let tier = self.determine_tier(tool);
        let cost_mb = SysResourceManager::estimate_cost_mb(&tool.category);

        if !self.res_mgr.can_allocate(cost_mb) {
            anyhow::bail!("Backpressure: RAM insuficiente para '{}' ({} MB).", tool.name, cost_mb);
        }

        match tier {
            ExecutionTier::StrictDocker => {
                info!("🐳 [Sandbox-Stream] '{}' vía Docker. Límite: {}m", tool.name, cost_mb);
                let mut cmd = Command::new("docker");
                cmd.arg("run")
                   .arg("--rm")
                   .arg("-i") // Interactivo para pipes
                   .arg(format!("--memory={}m", cost_mb))
                   .arg("redteam-tools:v4-slim") 
                   .arg(&tool.name)
                   .args(args)
                   .stdout(std::process::Stdio::piped())
                   .stderr(std::process::Stdio::piped());

                cmd.spawn().context("Fallo al spawnear Docker Sandbox")
            },
            ExecutionTier::FluidLocal => {
                info!("⚡ [Sandbox-Stream] '{}' Nativo (ProcessGuard).", tool.name);
                let mut cmd = Command::new(&tool.name);
                cmd.args(args)
                   .stdout(std::process::Stdio::piped())
                   .stderr(std::process::Stdio::piped());

                unsafe {
                    cmd.pre_exec(|| {
                        libc::setpgid(0, 0);
                        Ok(())
                    });
                }
                cmd.spawn().context("Fallo al spawnear herramienta nativa")
            }
        }
    }

    pub async fn execute_tool(&self, tool: &BlackArchTool, args: &[String]) -> Result<String> {
        let mut child = self.execute_tool_streamed(tool, args).await?;
        let output = child.wait_with_output().await.context("Error esperando salida del sandbox")?;
        
        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Error en sandbox tool '{}': {}", tool.name, err);
        }
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }
}
