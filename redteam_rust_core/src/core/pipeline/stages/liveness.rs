use tokio::sync::mpsc;
use tracing::{info, warn};
use futures::StreamExt;
use crate::models::{TargetHost, TargetStatus, TargetType};
use crate::utils::{LivenessChecker, liveness::is_safe_ip};

pub fn spawn_liveness_stage(
    rx: mpsc::Receiver<TargetHost>,
    scan_tx: mpsc::Sender<TargetHost>,
    sink_tx: mpsc::Sender<TargetHost>,
    liveness_checker: LivenessChecker,
    concurrency: usize,
    shutdown_token: tokio_util::sync::CancellationToken,
) -> tokio::task::JoinHandle<()> {
    let mut rx = rx;
    let token = shutdown_token.clone();
    
    tokio::spawn(async move {
        let stream = async_stream::stream! {
            while let Some(t) = rx.recv().await { 
                yield t; 
                if token.is_cancelled() { break; } 
            }
        };
        tokio::pin!(stream);
        
        stream.for_each_concurrent(concurrency, move |mut target| {
            let checker = liveness_checker.clone(); 
            let scan_tx = scan_tx.clone(); 
            let sink_tx = sink_tx.clone(); 
            let token = shutdown_token.clone();
            async move {
                if target.target_type == TargetType::Mobile || target.target_type == TargetType::Container {
                    let _ = scan_tx.send(target).await;
                    return;
                }

                if let Some(ip) = tokio::select! { 
                    res = checker.is_live(&target.host) => res, 
                    _ = token.cancelled() => return 
                } {
                    if !is_safe_ip(&ip) { 
                        warn!("🛡️ V13: Blocked unsafe IP {} for host {}", ip, target.host);
                        target.status = TargetStatus::Dead; 
                        let _ = sink_tx.send(target).await; 
                        return; 
                    }
                    target.ip = Some(ip.to_string()); 
                    target.resolved_ip = Some(ip.to_string());

                    // CDN Check
                    let cdn_checker = crate::plugins::reconnaissance::active::cdncheck::CdnCheckScanner::new();
                    if let Ok(true) = cdn_checker.is_cdn(&ip.to_string()).await {
                         info!("🛡️ CDN GATE: Target {} detected behind CDN/Cloud.", target.host);
                         target.skip_heavy_scan = true;
                    }

                    let _ = scan_tx.send(target).await;
                } else { 
                    warn!("⚠️ V13: Resolution failed for host {}.", target.host);
                    target.status = TargetStatus::Dead; 
                    let _ = sink_tx.send(target).await; 
                }
            }
        }).await;
    })
}
