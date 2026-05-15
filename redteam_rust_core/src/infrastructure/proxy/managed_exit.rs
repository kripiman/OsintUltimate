use std::time::SystemTime;
use tracing::{info, warn, error};
use anyhow::Result;
use crate::utils::config::ProxyMode;
use super::manager::ProxyManager;
use super::types::ManagedExit;

impl ProxyManager {
    pub fn add_managed_exit_with_auth(&self, ip: String, user: &str, pass: &str) {
        let max_nodes = (self.proxy_pool_size as usize * 2).max(10);
        if self.managed_exits.len() >= max_nodes {
            warn!("⚠️ Managed exit pool full ({} nodes). Rejecting {}", self.managed_exits.len(), ip);
            return;
        }
        let mut local_port = None;
        if self.proxy_mode == ProxyMode::Hysteria {
            let port = 10000 + (rand::random::<u16>() % 10000);
            if self.spawn_local_proxy_client(&ip, port, pass).is_ok() {
                local_port = Some(port);
            }
        }

        self.managed_exits.insert(ip.clone(), ManagedExit {
            last_seen: SystemTime::now(),
            user: Some(user.to_string()),
            pass: Some(pass.to_string()),
            local_port,
        });
        info!("🚀 ProxyManager: Active DO Managed Exit added with professional authentication: {} (Local Port: {:?})", ip, local_port);
    }

    pub fn add_managed_exit(&self, ip: String) {
        let max_nodes = (self.proxy_pool_size as usize * 2).max(10);
        if self.managed_exits.len() >= max_nodes {
            warn!("⚠️ Managed exit pool full ({} nodes). Rejecting {}", self.managed_exits.len(), ip);
            return;
        }
        self.managed_exits.insert(ip.clone(), ManagedExit {
            last_seen: SystemTime::now(),
            user: None,
            pass: None,
            local_port: None,
        });
        info!("🚀 ProxyManager: Active DO Managed Exit added (Anonymous): {}", ip);
    }
    
    pub fn get_managed_exits(&self) -> Vec<String> {
        self.managed_exits.iter().map(|e| e.key().clone()).collect()
    }

    pub(crate) fn spawn_local_proxy_client(&self, remote_ip: &str, local_port: u16, auth: &str) -> Result<()> {
        use tokio::process::Command;
        use crate::utils::downloader::ensure_hysteria_binary;
        
        let remote_ip = remote_ip.to_string();
        let auth = auth.to_string();

        tokio::spawn(async move {
            let bin = match ensure_hysteria_binary().await {
                Ok(b) => b,
                Err(e) => {
                    error!("❌ STEALTH: Failed to ensure Hysteria binary: {}", e);
                    return;
                }
            };

            info!("🛡️ STEALTH: Spawning local Hysteria client for {} on port {}...", remote_ip, local_port);
            
            let config_content = format!(r#"
server: {}:1080
auth: {}
socks5:
  listen: 127.0.0.1:{}
transport:
  udp:
    hop: true
"#, remote_ip, auth, local_port);

            let config_path = std::env::temp_dir().join(format!("hysteria_{}.yaml", local_port));
            if let Err(e) = tokio::fs::write(&config_path, config_content).await {
                error!("❌ STEALTH: Failed to write Hysteria client config: {}", e);
                return;
            }

            match Command::new(bin)
                .arg("client")
                .arg("-c")
                .arg(&config_path)
                .kill_on_drop(true)
                .spawn() {
                    Ok(mut child) => {
                        info!("🚀 STEALTH: Hysteria local client PID {:?} established for {}", child.id(), remote_ip);
                        let _ = child.wait().await;
                    }
                    Err(e) => error!("❌ STEALTH: Failed to spawn Hysteria client: {}", e),
                }
        });

        Ok(())
    }
}
