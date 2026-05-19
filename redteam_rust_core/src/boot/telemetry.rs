use crate::boot::cli::Args;
use anyhow::Context;
use std::time::Duration;

pub fn init(args: &Args) -> anyhow::Result<()> {
    redteam_rust_core::utils::init_telemetry(args.otel_endpoint.clone(), args.json_logs, None)
        .context("Failed to initialize telemetry")?;

    // 📊 ROI Baseline Collection (Fase 0): Periodic metrics dump to logs
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(300));
        loop {
            interval.tick().await;
            redteam_rust_core::utils::telemetry::dump_metrics();
        }
    });

    Ok(())
}
