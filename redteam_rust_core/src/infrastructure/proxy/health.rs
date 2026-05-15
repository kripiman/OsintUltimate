use std::time::Duration;
use tracing::warn;
use super::manager::ProxyManager;

impl ProxyManager {
    pub(crate) fn start_health_checker(&mut self) {
        if let Some(h) = self.health_checker_handle.take() {
            h.abort();
        }
        let managed_exits = self.managed_exits.clone();
        
        let handle = tokio::spawn(async move {
            loop {
                let sleep_secs = {
                    let mut rng = rand::thread_rng();
                    rand::Rng::gen_range(&mut rng, 30..60)
                };
                tokio::time::sleep(Duration::from_secs(sleep_secs)).await;

                let mut to_prune = Vec::new();
                for entry in managed_exits.iter() {
                    let ip = entry.key().clone();
                    let exit = entry.value();
                    
                    let elapsed = exit.last_seen.elapsed().unwrap_or(Duration::from_secs(0));
                    if elapsed.as_secs() > 43200 { 
                         to_prune.push(ip);
                         continue;
                    }

                    let addr_str = format!("{}:1080", ip);
                    match tokio::time::timeout(Duration::from_secs(3), tokio::net::TcpStream::connect(&addr_str)).await {
                        Ok(Ok(_)) => {}
                        _ => {
                            warn!("🛡️ SUPERVISOR: Managed exit {} failed TCP health check. Pruning.", ip);
                            to_prune.push(ip);
                        }
                    }
                }

                for ip in to_prune {
                    managed_exits.remove(&ip);
                }
            }
        });
        self.health_checker_handle = Some(handle.abort_handle());
    }
}
