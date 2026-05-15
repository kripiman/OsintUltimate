use tracing::{info, warn};
use anyhow::{Result, Context};
use futures::StreamExt;
use super::manager::ProxyManager;

impl ProxyManager {
    pub fn kill_egress(&self) {
        self.egress_killed.store(true, std::sync::atomic::Ordering::SeqCst);
        warn!("[EGRESS-KILL] Egress circuit breaker triggered. All outbound blocked.");
    }

    pub async fn listen_for_kill_switch(&self, nats_url: &str, node_id: &str) -> Result<()> {
        let client = async_nats::connect(nats_url).await
            .context("Failed to connect to NATS for kill-switch listener")?;
        
        let egress_killed = self.egress_killed.clone();
        let mut subscriber = client.subscribe("mimikri.control.kill_egress".to_string()).await
            .context("Failed to subscribe to global kill-switch")?;

        info!("🔱 SOVEREIGN: Node {} listening for global kill-switch signals...", node_id);
        
        tokio::spawn(async move {
            while let Some(message) = subscriber.next().await {
                let sender = String::from_utf8_lossy(&message.payload);
                warn!("🚨 GLOBAL KILL-SWITCH RECEIVED! Triggered by node: {}. Locking egress.", sender);
                egress_killed.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        });

        Ok(())
    }

    pub async fn broadcast_kill_switch(&self, nats_url: &str, node_id: &str) -> Result<()> {
        self.kill_egress();
        let client = async_nats::connect(nats_url).await?;
        client.publish("mimikri.control.kill_egress".to_string(), node_id.to_string().into()).await?;
        info!("📢 GLOBAL KILL-SWITCH BROADCAST: Signal sent to NATS mesh.");
        Ok(())
    }

    pub fn is_egress_killed(&self) -> bool {
        self.egress_killed.load(std::sync::atomic::Ordering::SeqCst)
    }
}
