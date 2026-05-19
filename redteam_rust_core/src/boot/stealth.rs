use crate::boot::cli::Args;
use redteam_rust_core::core::engine::RedTeamEngine;
use redteam_rust_core::utils::config::Config;
use std::sync::Arc;
use anyhow::Result;

pub async fn init(engine: &RedTeamEngine, args: &Args, utils_config: &Config) -> Result<()> {
    // --- STEALTH INFRASTRUCTURE SETUP (V14.1) ---
    if let Ok(token) = utils_config.require_do_token() {
        engine.init_stealth_infrastructure(token.clone()).await?;

        // Global Kill-Switch Integration
        if let Some(ref nats_url) = args.nats_url {
            let node_id = args.node_id.clone().unwrap_or_else(|| "local".to_string());
            let _ = engine.proxy_manager().listen_for_kill_switch(nats_url, &node_id).await;
        }

        let pm_clean = engine.proxy_manager();
        let shutdown_mgr = Arc::new(redteam_rust_core::core::orchestrator::lifecycle::ShutdownManager::new(
            engine.shutdown_token(),
            Some(pm_clean.clone()),
        ));

        let token_clean = token.clone();
        let pm_clean_hook = pm_clean.clone();
        shutdown_mgr.add_hook(move || {
            Box::pin(async move {
                let do_client = redteam_rust_core::infrastructure::digital_ocean::DigitalOceanClient::new(token_clean, pm_clean_hook);
                if let Err(e) = do_client.destroy_all_ephemeral_droplets().await {
                    tracing::error!("❌ [KILL-SWITCH] Failed to clean up DigitalOcean droplets: {}", e);
                } else {
                    tracing::info!("🛡️ [KILL-SWITCH] Ephemeral droplets destroyed successfully.");
                }
            })
        }).await;

        tokio::spawn(async move {
            shutdown_mgr.wait_for_signal().await;
            std::process::exit(0);
        });
    }
    
    Ok(())
}
