#![warn(clippy::all)]

pub mod menu;
mod boot;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    boot::cli::binary_health_check().await;
    let args = boot::cli::parse();
    boot::telemetry::init(&args)?;
    boot::runtime::dispatch(args).await
}
