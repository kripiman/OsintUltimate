use anyhow::{Context, Result};
use opentelemetry::KeyValue;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{trace, Resource};
use tracing_subscriber::{layer::SubscriberExt, EnvFilter, Registry};
use tracing_subscriber::fmt;
use std::io;
use std::sync::Arc;
use once_cell::sync::Lazy;
use regex::Regex;
use tonic::transport::Endpoint;
use tower::service_fn;
use crate::utils::proxy::ProxyManager;
use tracing::info;

use std::sync::atomic::{AtomicU64, Ordering};

pub static METRIC_FINDINGS_IN: AtomicU64 = AtomicU64::new(0);
pub static METRIC_FPF_DROPS: AtomicU64 = AtomicU64::new(0);
pub static METRIC_LOCAL_QWEN_TRIAGE: AtomicU64 = AtomicU64::new(0);
pub static METRIC_MID_LLM_CALLS: AtomicU64 = AtomicU64::new(0);
pub static METRIC_PREMIUM_LLM_CALLS: AtomicU64 = AtomicU64::new(0);
pub static METRIC_MANUAL_SUBMISSIONS: AtomicU64 = AtomicU64::new(0);

static SENSITIVE_REGEX: Lazy<Regex> = Lazy::new(|| {
    // Patterns for: Proxy Auth (user:pass@), Shodan/Censys Keys (32 chars hex), etc.
    Regex::new(r"(?i)(:[^:@\s/]+@|key=[a-f0-9]{32}|api_key=[a-f0-9]{32}|password=[^\s&]+)").unwrap()
});

struct MaskingWriter<W> {
    inner: W,
}

impl<W: io::Write> io::Write for MaskingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // QA-013 FIX: Fast-path bypass — skip regex if no sensitive byte markers are present.
        // This avoids the costly regex scan and UTF-8 conversion on ~95% of log lines.
        let has_at = buf.contains(&b'@');
        let has_key = buf.windows(4).any(|w| w.eq_ignore_ascii_case(b"key="));
        let has_pass = buf.windows(9).any(|w| w.eq_ignore_ascii_case(b"password="));
        
        if !has_at && !has_key && !has_pass {
            return self.inner.write(buf);
        }
        
        let s = String::from_utf8_lossy(buf);
        let masked = SENSITIVE_REGEX.replace_all(&s, |caps: &regex::Captures| {
            let cap = caps.get(0).unwrap().as_str();
            if cap.starts_with(':') {
                ":***MASKED***@".to_string()
            } else if cap.contains('=') {
                let parts: Vec<&str> = cap.split('=').collect();
                format!("{}***MASKED***", parts[0])
            } else {
                "***MASKED***".to_string()
            }
        });
        self.inner.write_all(masked.as_bytes())?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

struct MaskingMakeWriter;
impl<'a> fmt::MakeWriter<'a> for MaskingMakeWriter {
    type Writer = MaskingWriter<io::Stdout>;
    fn make_writer(&self) -> Self::Writer {
        MaskingWriter { inner: io::stdout() }
    }
}

pub fn init_telemetry(endpoint: Option<String>, json_logs: bool, pm: Option<Arc<ProxyManager>>) -> Result<()> {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "redteam_rust_core=info".into());

    if let Some(endpoint_url) = endpoint {
        // OpenTelemetry Setup
        let tracer_result = if let Some(ref proxy_mgr) = pm {
            // PROXY-AWARE TELEMETRY (V14.1)
            let pm_inner = proxy_mgr.clone();
            let endpoint_url_clone = endpoint_url.clone();
            
            let channel = Endpoint::from_shared(endpoint_url.clone())?
                .connect_with_connector_lazy(service_fn(move |_| {
                    let pm = pm_inner.clone();
                    let url = endpoint_url_clone.clone();
                    async move {
                        let parsed = url::Url::parse(&url).map_err(std::io::Error::other)?;
                        let host = parsed.host_str().unwrap_or("localhost");
                        let port = parsed.port_or_known_default().unwrap_or(4317);
                        pm.tcp_connect_proxied(host, port).await
                            .map(hyper_util::rt::TokioIo::new)
                            .map_err(std::io::Error::other)
                    }
                }));

            opentelemetry_otlp::new_pipeline()
                .tracing()
                .with_exporter(
                    opentelemetry_otlp::new_exporter()
                        .tonic()
                        .with_channel(channel),
                )
                .with_trace_config(
                    trace::Config::default().with_resource(Resource::new(vec![
                        KeyValue::new("service.name", "redteam_rust_core"),
                    ])),
                )
                .install_batch(opentelemetry_sdk::runtime::Tokio)
        } else {
            // Direct connection (only for non-stealth or local debug)
            opentelemetry_otlp::new_pipeline()
                .tracing()
                .with_exporter(
                    opentelemetry_otlp::new_exporter()
                        .tonic()
                        .with_endpoint(&endpoint_url),
                )
                .with_trace_config(
                    trace::Config::default().with_resource(Resource::new(vec![
                        KeyValue::new("service.name", "redteam_rust_core"),
                    ])),
                )
                .install_batch(opentelemetry_sdk::runtime::Tokio)
        };

        match tracer_result {
            Ok(provider) => {
                use opentelemetry::trace::TracerProvider as _;
                let tracer = provider.tracer("redteam_rust_core");
                let telemetry = tracing_opentelemetry::layer().with_tracer(tracer);

                let subscriber = Registry::default()
                    .with(env_filter)
                    .with(telemetry)
                    .with(fmt::layer().with_writer(MaskingMakeWriter)); // Also log to stdout with masking

                tracing::subscriber::set_global_default(subscriber)
                    .context("Failed to set global subscriber with OpenTelemetry")?;
            },
            Err(e) => {
                // V8 FIX (DEBT-005): Fallback properly without panicking if external OTLP server is dead
                eprintln!("⚠️ WARNING: Failed to initialize OpenTelemetry on {}: {}. Falling back to standard logs.", endpoint_url, e);
                let subscriber = fmt::Subscriber::builder()
                    .with_env_filter(env_filter)
                    .with_writer(MaskingMakeWriter)
                    .with_target(false)
                    .with_thread_ids(true)
                    .finish();
                tracing::subscriber::set_global_default(subscriber)
                    .context("Failed to set global subscriber after OTLP failure")?;
            }
        }
    } else if json_logs {
        // Structured JSON Logs
        let subscriber = fmt::Subscriber::builder()
            .with_env_filter(env_filter)
            .with_writer(MaskingMakeWriter)
            .json()
            .finish();
            
        tracing::subscriber::set_global_default(subscriber)
            .context("Failed to set global JSON subscriber")?;
            
    } else {
        // Standard Pretty Logs
        let subscriber = fmt::Subscriber::builder()
            .with_env_filter(env_filter)
            .with_writer(MaskingMakeWriter)
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

/// Periodically dumps telemetry to logs for ROI baseline collection (Fase 0)
pub fn dump_metrics() {
    info!(
        "📊 ROI METRICS: [Findings_In: {}] [FPF_Drops: {}] [Local_Triage: {}] [Mid_Calls: {}] [Premium_Calls: {}] [Manual_Submissions: {}]",
        METRIC_FINDINGS_IN.load(Ordering::Relaxed),
        METRIC_FPF_DROPS.load(Ordering::Relaxed),
        METRIC_LOCAL_QWEN_TRIAGE.load(Ordering::Relaxed),
        METRIC_MID_LLM_CALLS.load(Ordering::Relaxed),
        METRIC_PREMIUM_LLM_CALLS.load(Ordering::Relaxed),
        METRIC_MANUAL_SUBMISSIONS.load(Ordering::Relaxed),
    );
}
