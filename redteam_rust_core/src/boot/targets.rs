use crate::boot::cli::Args;
use redteam_rust_core::models::{TargetHost, TargetStatus};
use redteam_rust_core::utils::config::Config;
use redteam_rust_core::utils::validate_target;
use tracing::{info, error};
use std::sync::Arc;
use anyhow::Result;
use futures::StreamExt;

pub async fn build_target_stream(
    args: &Args,
    utils_config: &Config,
    injection_rx: tokio::sync::mpsc::Receiver<TargetHost>
) -> Result<futures::stream::BoxStream<'static, TargetHost>> {
    let cli_scope_id = Arc::new(args.scope_id.clone().unwrap_or_default());
    
    let certstream_rx = if !utils_config.certstream_keywords.is_empty() {
        info!("🔱 V14.2 SOVEREIGN: Activating CertStream Daemon for keywords: {:?}", utils_config.certstream_keywords);
        Some(redteam_rust_core::infrastructure::certstream::CertStreamDaemon::spawn(utils_config.certstream_keywords.clone()))
    } else {
        None
    };

    let cli_scope_id_stream = cli_scope_id.clone();
    let target_stream: futures::stream::BoxStream<'static, TargetHost> = if let Some(apk_path) = args.apk.clone() {
        let cli_scope_id = cli_scope_id_stream.clone();
        let package_name = apk_path.split('/').next_back().unwrap_or("mobile_app").to_string();
        Box::pin(futures::stream::iter(vec![TargetHost {
            host: package_name,
            ip: None,
            resolved_ip: None,
            status: TargetStatus::Pending,
            target_type: redteam_rust_core::models::TargetType::Mobile,
            file_path: Some(apk_path),
            user: None,
            findings: Arc::new(Vec::new()),
            tool_suggestions: Arc::new(Vec::new()),
            tactical_context: Arc::new(serde_json::json!({})),
            extra_data: Arc::new(serde_json::json!({})),
            version: 0,
            skip_heavy_scan: false,
            scan_id: None, scope_id: (*cli_scope_id).clone(),
        }]))
    } else if let Some(image_ref) = args.image.clone() {
        let cli_scope_id = cli_scope_id_stream.clone();
        Box::pin(futures::stream::iter(vec![TargetHost {
            host: image_ref,
            ip: None,
            resolved_ip: None,
            status: TargetStatus::Pending,
            target_type: redteam_rust_core::models::TargetType::Container,
            file_path: None,
            user: None,
            findings: Arc::new(Vec::new()),
            tool_suggestions: Arc::new(Vec::new()),
            tactical_context: Arc::new(serde_json::json!({})),
            extra_data: Arc::new(serde_json::json!({})),
            version: 0,
            skip_heavy_scan: false,
            scan_id: None, scope_id: (*cli_scope_id).clone(),
        }]))
    } else if let Some(input_path) = args.input.clone() {
        let cli_scope_id = cli_scope_id_stream.clone();
        let file = tokio::fs::File::open(&input_path).await?;
        let reader = tokio::io::BufReader::new(file);
        tokio_stream::wrappers::LinesStream::new(tokio::io::AsyncBufReadExt::lines(reader))
            .filter_map(|res| async move { 
                res.ok().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()) 
            })
            .filter(|t: &String| { 
                let t_clone = t.clone();
                let valid = validate_target(&t_clone); 
                if !valid { error!("❌ Skipping invalid target: {}", t_clone); } 
                async move { valid } 
            })
            .map(move |t: String| {
                let target_type = if t.contains("://") || t.contains('.') { redteam_rust_core::models::TargetType::Web }
                else if t.contains(':') { redteam_rust_core::models::TargetType::Network }
                else { redteam_rust_core::models::TargetType::Host };
 
                TargetHost {
                    host: t, ip: None, resolved_ip: None, status: TargetStatus::Pending, target_type,
                    file_path: None,
                    user: None,
                    findings: Arc::new(Vec::new()), tool_suggestions: Arc::new(Vec::new()),
                    tactical_context: Arc::new(serde_json::json!({})), extra_data: Arc::new(serde_json::json!({})),
                    version: 0,
                    skip_heavy_scan: false,
                    scan_id: None, scope_id: (*cli_scope_id).clone(),
                }
            })
            .boxed()
    } else if let Some(target) = args.target.clone() {
        let cli_scope_id = cli_scope_id_stream.clone();
        let valid = validate_target(&target);
        if !valid {
            anyhow::bail!("Invalid target provided: {}", target);
        }
        let target_type = if args.image.is_some() {
            redteam_rust_core::models::TargetType::Container
        } else if target.contains("://") || target.contains('.') {
            redteam_rust_core::models::TargetType::Web
        } else if target.contains(':') && target.matches(':').count() == 1 && !target.starts_with('[') && !target.contains('.') {
            redteam_rust_core::models::TargetType::Container
        } else if target.contains(':') {
            redteam_rust_core::models::TargetType::Network
        } else {
            redteam_rust_core::models::TargetType::Host
        };
 
        Box::pin(futures::stream::iter(vec![TargetHost {
            host: target,
            ip: None,
            resolved_ip: None,
            status: TargetStatus::Pending,
            target_type,
            file_path: None,
            user: None,
            findings: Arc::new(Vec::new()),
            tool_suggestions: Arc::new(Vec::new()),
            tactical_context: Arc::new(serde_json::json!({})),
            extra_data: Arc::new(serde_json::json!({})),
            version: 0,
            skip_heavy_scan: false,
            scan_id: None, scope_id: (*cli_scope_id).clone(),
        }]))
    } else if certstream_rx.is_some() || args.dashboard.is_some() {
        info!("📡 Waiting for targets from CertStream or Dashboard...");
        futures::stream::empty().boxed()
    } else {
        anyhow::bail!("Either --target, --input, --apk, --dashboard or CERTSTREAM_KEYWORDS must be provided.");
    };

    // Base stream
    let mut target_hosts = target_stream;

    // Merge Injection Stream (Dashboard/Internal)
    let injection_stream = tokio_stream::wrappers::ReceiverStream::new(injection_rx);
    target_hosts = futures::stream::select(target_hosts, injection_stream).boxed();

    // Merge CertStream if active
    if let Some(rx) = certstream_rx {
        let cli_scope_id_cs = cli_scope_id.clone();
        info!("📡 CertStream integration active. Real-time targets will be merged.");
        let cs_stream = tokio_stream::wrappers::ReceiverStream::new(rx)
            .filter(|t: &String| { 
                let t_clone = t.clone();
                let valid = validate_target(&t_clone); 
                if !valid { error!("❌ Skipping invalid target: {}", t_clone); } 
                async move { valid } 
            })
            .map(move |t: String| {
                let target_type = if t.contains("://") || t.contains('.') { redteam_rust_core::models::TargetType::Web }
                else if t.contains(':') { redteam_rust_core::models::TargetType::Network }
                else { redteam_rust_core::models::TargetType::Host };

                TargetHost {
                    host: t, ip: None, resolved_ip: None, status: TargetStatus::Pending, target_type,
                    file_path: None,
                    user: None,
                    findings: Arc::new(Vec::new()), tool_suggestions: Arc::new(Vec::new()),
                    tactical_context: Arc::new(serde_json::json!({})), extra_data: Arc::new(serde_json::json!({})),
                    version: 0,
                    skip_heavy_scan: false,
                    scan_id: None, scope_id: (*cli_scope_id_cs).clone(),
                }
            });
        target_hosts = futures::stream::select(target_hosts, cs_stream).boxed();
    }

    Ok(target_hosts)
}
