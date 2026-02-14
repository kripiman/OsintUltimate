use anyhow::{Context, Result};
use opentelemetry::KeyValue;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{trace, Resource};
use tracing_subscriber::{layer::SubscriberExt, EnvFilter, Registry};
use tracing_subscriber::fmt;

pub fn init_telemetry(endpoint: Option<String>, json_logs: bool) -> Result<()> {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "redteam_rust_core=info".into());

    if let Some(endpoint_url) = endpoint {
        // OpenTelemetry Setup
        let tracer = opentelemetry_otlp::new_pipeline()
            .tracing()
            .with_exporter(
                opentelemetry_otlp::new_exporter()
                    .tonic()
                    .with_endpoint(endpoint_url),
            )
            .with_trace_config(
                trace::config().with_resource(Resource::new(vec![
                    KeyValue::new("service.name", "redteam_rust_core"),
                ])),
            )
            .install_batch(opentelemetry_sdk::runtime::Tokio)
            .context("Failed to install OpenTelemetry tracer")?;

        let telemetry = tracing_opentelemetry::layer().with_tracer(tracer);

        let subscriber = Registry::default()
            .with(env_filter)
            .with(telemetry)
            .with(fmt::layer()); // Also log to stdout

        tracing::subscriber::set_global_default(subscriber)
            .context("Failed to set global subscriber with OpenTelemetry")?;
        
    } else if json_logs {
        // Structured JSON Logs
        let subscriber = fmt::Subscriber::builder()
            .with_env_filter(env_filter)
            .json()
            .finish();
            
        tracing::subscriber::set_global_default(subscriber)
            .context("Failed to set global JSON subscriber")?;
            
    } else {
        // Standard Pretty Logs
        let subscriber = fmt::Subscriber::builder()
            .with_env_filter(env_filter)
            .with_target(false)
            .with_thread_ids(true)
            .finish();
            
        tracing::subscriber::set_global_default(subscriber)
            .context("Failed to set global subscriber")?;
    }

    Ok(())
}

pub fn shutdown_telemetry() {
    opentelemetry::global::shutdown_tracer_provider();
}
