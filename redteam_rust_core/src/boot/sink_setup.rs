use crate::boot::cli::Args;
use redteam_rust_core::core::sink::{MultiSink, JsonlSink, PostgresSink, TacticalWebhookSink, DataSink};
use redteam_rust_core::core::engine::{RedTeamEngine, app::EngineConfig};
use redteam_rust_core::utils::config::Config;
use redteam_rust_core::utils::security::is_ssrf_safe_host_async;
use tracing::info;
use anyhow::Result;

pub async fn build_multi_sink(
    args: &Args, 
    engine_config: &EngineConfig, 
    utils_config: &Config,
    engine: &RedTeamEngine
) -> Result<Box<dyn DataSink>> {
    let mut multi_sink = MultiSink::new();
    
    // V14.2: Bug Bounty Automated Submission Sink
    if engine_config.h1_api_key.is_some() || engine_config.bugcrowd_api_key.is_some() || engine_config.intigriti_token.is_some() {
        multi_sink.add(Box::new(redteam_rust_core::core::sink::BountySink::new(
            engine_config.h1_username.clone(),
            engine_config.h1_api_key.clone(),
            engine_config.bugcrowd_api_key.clone(),
            engine_config.intigriti_token.clone(),
            engine_config.bb_program_handle.clone(),
        )));
        info!("🚀 [BountySink] Automated platform submission routing attached.");
    }

    // V14.8: NATS Mesh Sink
    if let Some(ref nats_url) = args.nats_url {
        if let Ok(nats_sink) = redteam_rust_core::core::sink::nats_sink::NatsSink::new(nats_url, "mimikri").await {
            multi_sink.add(Box::new(nats_sink));
            info!("🔱 [NatsSink] Decentralized mesh routing attached.");
        }
    }

    if let Some(ref db_url) = args.postgres_url {
        let sink = PostgresSink::new(db_url).await?;
        // Reuse PostgresSink's pool — avoids double connection
        redteam_rust_core::utils::api_budget::ApiBudgetRegistry::init(utils_config, Some(sink.pool().clone()));
        redteam_rust_core::utils::api_cache::ApiCache::init(sink.pool().clone());
        redteam_rust_core::utils::shodan_keyring::ShodanKeyring::init(utils_config);
        multi_sink.add(Box::new(sink));
    } else {
        redteam_rust_core::utils::api_budget::ApiBudgetRegistry::init(utils_config, None);
        redteam_rust_core::utils::shodan_keyring::ShodanKeyring::init(utils_config);
        multi_sink.add(Box::new(JsonlSink::new(&args.jsonl_output).await?));
    }

    if let Ok(c2_env) = std::env::var("C2_URL") {
        if let Ok(parsed_url) = url::Url::parse(&c2_env) {
            if parsed_url.scheme() == "https" && is_ssrf_safe_host_async(parsed_url.host_str().unwrap_or("")).await {
                let c2_token = std::env::var("C2_TOKEN").ok();
                multi_sink.add(Box::new(TacticalWebhookSink::new(parsed_url.to_string(), c2_token, engine.proxy_manager())?));
            }
        }
    }

    // --- DISCORD NOTIFICATIONS (V14.1 Quick Alerts) ---
    if let Some(webhook_url) = utils_config.discord_webhook_url.clone() {
        if webhook_url.starts_with("https://discord.com/api/webhooks/") {
            use redteam_rust_core::core::notifications::discord::DiscordSink;
            multi_sink.add(Box::new(DiscordSink::new(webhook_url, engine.proxy_manager())));
            info!("🔔 [DiscordSink] Notification routing attached for High/Critical findings.");
        }
    }

    // --- ACTIVITY LOG (TIMELINE) ---
    let timeline_path = std::path::PathBuf::from(&utils_config.workspace_dir).join("logs").join("timeline.jsonl");
    if let Ok(activity_log) = redteam_rust_core::utils::activity_log::ActivityLog::new(timeline_path).await {
        let act_log_arc = std::sync::Arc::new(activity_log);
        multi_sink.add(Box::new(redteam_rust_core::core::sink::TimelineSink::new(act_log_arc)));
        info!("📝 [TimelineSink] Acitivity log routing attached.");
    } else {
        tracing::warn!("⚠️ [TimelineSink] Failed to initialize ActivityLog at workspace/logs/timeline.jsonl");
    }

    Ok(Box::new(multi_sink))
}
