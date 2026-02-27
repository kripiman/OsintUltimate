use crate::core::orchestrator::Orchestrator;
use crate::core::sink::DataSink;
use crate::models::{TargetHost, TargetStatus, Finding, Category, Severity, ScanMetadata};
use crate::plugins::{ScannerPlugin, DiscoveryPlugin};
use crate::utils::liveness::{LivenessChecker, is_safe_ip};
use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn, error, debug};
use futures::stream::StreamExt;

pub struct Pipeline {
    concurrency: usize,
    discovery_plugins: Arc<Vec<Box<dyn DiscoveryPlugin>>>,
    plugins: Vec<Box<dyn ScannerPlugin>>,
    sink: Box<dyn DataSink>,
    shutdown_token: CancellationToken,
    liveness_checker: LivenessChecker,
    command_line: String,
}

impl Pipeline {
    pub fn builder() -> PipelineBuilder {
        PipelineBuilder::new()
    }

    /// Runs the 4-stage pipeline: Discovery -> Liveness -> Scanning -> Sink
    pub async fn run(self, targets: Vec<TargetHost>) -> Result<()> {
        info!("🚀 Starting Pipeline with {} plugins...", self.plugins.len());
        
        // HIGH-007 FIX: Write metadata as the first line in the sink
        let mut sink = self.sink;
        sink.write_metadata(&ScanMetadata::new(&self.command_line)).await?;

        // CRIT-002 FIX: Implement real backpressure by reducing channel size.
        // 10,000 was saturating RAM. Now bound by concurrency with a hard cap (AUDIT-004).
        let channel_size = (self.concurrency * 2).clamp(100, 1000);
        
        let (osint_tx, osint_rx) = mpsc::channel::<TargetHost>(channel_size);
        let (liveness_tx, liveness_rx) = mpsc::channel::<TargetHost>(channel_size);
        let (scan_tx, scan_rx) = mpsc::channel::<TargetHost>(channel_size);
        let (sink_tx, mut sink_rx) = mpsc::channel::<TargetHost>(channel_size);

        let mut handles = Vec::new();
        
        // --- STAGE 1: Discovery (OSINT & Resolvers) ---
        let seen_domains = Arc::new(dashmap::DashSet::new());
        let discovery_token = self.shutdown_token.clone();
        let discovery_plugins = self.discovery_plugins.clone();
        
        handles.push(tokio::spawn(async move {
            let mut rx = osint_rx;
            while let Some(mut target) = rx.recv().await {
                if discovery_token.is_cancelled() { break; }
                
                // Track the root target itself and skip if already seen
                if !seen_domains.insert(target.host.clone()) {
                    debug!("Skipping already seen root target: {}", target.host);
                    continue;
                }

                // AUDIT-004 FIX: Run all discovery plugins in parallel
                let discovery_futures = discovery_plugins.iter().map(|plugin| {
                    let target_ref = &target;
                    async move {
                        (plugin.name(), plugin.discover(target_ref).await)
                    }
                });

                let results = futures::future::join_all(discovery_futures).await;

                for (name, res) in results {
                    match res {
                        Ok(subdomains) => {
                            for sub in subdomains {
                                if seen_domains.insert(sub.clone()) {
                                    // Log as finding on root
                                    target.findings.push(Finding::new(
                                        "DISCOVERED_SUBDOMAIN",
                                        Category::Recon,
                                        Severity::Info,
                                        &format!("Discovered via {}: {}", name, sub),
                                        serde_json::json!({
                                            "subdomain": sub.clone(),
                                            "source": name
                                        })
                                    ));
                                    
                                    let new_target = TargetHost {
                                        host: sub,
                                        ip: None,
                                        status: TargetStatus::Pending,
                                        findings: Vec::new(),
                                    };
                                    
                                    if let Err(e) = liveness_tx.send(new_target).await {
                                        warn!("Failed to inject discovered target into liveness queue: {}", e);
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            warn!("Discovery plugin {} failed on {}: {}", name, target.host, e);
                        }
                    }
                }
                
                // Forward the enriched root target.
                let _ = liveness_tx.send(target).await;
            }
        }));

        // Inject initial targets
        for t in targets {
            let _ = osint_tx.send(t).await;
        }
        drop(osint_tx); // Signals Stage 1 to eventually close

        // --- STAGE 2: Liveness ---
        let liveness_checker = self.liveness_checker;
        let liveness_token = self.shutdown_token.clone();
        let scan_tx_clone = scan_tx.clone();
        let sink_tx_err = sink_tx.clone();
        let liveness_concurrency = self.concurrency;

        // CRIT-002 FIX: Drop original sender immediately after moving its clone into Stage 2 task,
        // otherwise `Pipeline::run` holds the sender, and the `Pipeline::run` handle.await loop deadlocks.
        drop(scan_tx);

        let token_for_stream = liveness_token.clone();
        let token_for_each = liveness_token.clone();
        
        handles.push(tokio::spawn(async move {
            let stream = async_stream::stream! {
                let mut rx = liveness_rx;
                while let Some(t) = rx.recv().await {
                    yield t;
                    if token_for_stream.is_cancelled() { break; }
                }
            };

            tokio::pin!(stream);

            stream.for_each_concurrent(liveness_concurrency, move |mut target| {
                let checker = liveness_checker.clone();
                let scan_tx = scan_tx_clone.clone();
                let sink_tx = sink_tx_err.clone();
                let liveness_token_clone = token_for_each.clone();
                
                async move {
                    let ip_opt = tokio::select! {
                        res = checker.is_live(&target.host) => res,
                        _ = liveness_token_clone.cancelled() => return,
                    };
                    if let Some(ip) = ip_opt {
                        // HIGH-001 FIX: Enforce SSRF protection in Stage 2 before forwarding
                        if !is_safe_ip(&ip) {
                            warn!("⚠️ Blocking SSRF attempt: {} resolved to private IP {}", target.host, ip);
                            target.status = TargetStatus::Dead;
                            target.findings.push(Finding::new(
                                "SSRF_DETECTION",
                                Category::Vulnerability,
                                Severity::High,
                                &format!("Target {} resolved to restricted IP {} and was blocked", target.host, ip),
                                serde_json::json!({"ip": ip.to_string()})
                            ));
                            let _ = sink_tx.send(target).await;
                            return;
                        }

                        target.ip = Some(ip.to_string());
                        let _ = scan_tx.send(target).await;
                    } else {
                        target.status = TargetStatus::Dead;
                        target.findings.push(Finding::new(
                            "TARGET_UNREACHABLE",
                            Category::Availability,
                            Severity::Info,
                            &format!("Host {} appears to be offline or unreachable", target.host),
                            serde_json::json!({"host": target.host})
                        ));
                        let _ = sink_tx.send(target).await;
                    }
                }
            }).await;
        }));

        // --- STAGE 3: Scanning (Orchestrator) ---
        let mut orchestrator = Orchestrator::new(self.concurrency);
        for plugin in self.plugins.into_iter() {
            orchestrator.register_plugin(plugin);
        }
        let scan_token = self.shutdown_token.clone();
        let sink_tx_stage3 = sink_tx.clone();
        handles.push(tokio::spawn(async move {
            orchestrator.run(scan_rx, sink_tx_stage3, scan_token).await;
        }));
        
        drop(sink_tx);

        // --- STAGE 4: Sink ---
        // let mut sink = self.sink; // Already moved above for metadata
        let _sink_token = self.shutdown_token.clone();
        let sink_handle = tokio::spawn(async move {
            let mut count = 0;
            while let Some(target) = sink_rx.recv().await {
                if let Err(e) = sink.write(&target).await {
                    error!("Sink failed to write target {}: {}", target.host, e);
                }
                count += 1;
            }
            if let Err(e) = sink.close().await {
                error!("Sink failed to close properly: {}", e);
            }
            info!("📦 Sink closed. Total written: {}", count);
        });
        handles.push(sink_handle);

        // Wait for all stages
        for handle in handles {
            let _ = handle.await;
        }
        
        info!("✅ Pipeline execution complete.");
        Ok(())
    }
}

pub struct PipelineBuilder {
    concurrency: usize,
    discovery_plugins: Vec<Box<dyn DiscoveryPlugin>>,
    plugins: Vec<Box<dyn ScannerPlugin>>,
    sink: Option<Box<dyn DataSink>>,
    shutdown_token: CancellationToken,
    liveness_checker: Option<LivenessChecker>,
    command_line: String,
}

impl Default for PipelineBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl PipelineBuilder {
    pub fn new() -> Self {
        Self {
            concurrency: 10,
            discovery_plugins: Vec::new(),
            plugins: Vec::new(),
            sink: None,
            shutdown_token: CancellationToken::new(),
            liveness_checker: None,
            command_line: "OsintUltimate".to_string(),
        }
    }

    pub fn liveness_checker(mut self, checker: LivenessChecker) -> Self {
        self.liveness_checker = Some(checker);
        self
    }

    pub fn concurrency(mut self, c: usize) -> Self {
        self.concurrency = c;
        self
    }

    pub fn with_discovery(mut self, plugin: Box<dyn DiscoveryPlugin>) -> Self {
        self.discovery_plugins.push(plugin);
        self
    }

    pub fn with_plugin(mut self, plugin: Box<dyn ScannerPlugin>) -> Self {
        self.plugins.push(plugin);
        self
    }

    pub fn with_sink(mut self, sink: Box<dyn DataSink>) -> Self {
        self.sink = Some(sink);
        self
    }

    pub fn shutdown_token(mut self, token: CancellationToken) -> Self {
        self.shutdown_token = token;
        self
    }

    pub fn command_line(mut self, cmd: String) -> Self {
        self.command_line = cmd;
        self
    }

    pub fn build(self) -> Result<Pipeline> {
        let sink = self.sink.context("Pipeline requires a configured sink")?;
        let liveness_checker = self.liveness_checker.context("Pipeline requires a configured liveness checker")?;
        Ok(Pipeline {
            concurrency: self.concurrency,
            discovery_plugins: Arc::new(self.discovery_plugins),
            plugins: self.plugins,
            sink,
            shutdown_token: self.shutdown_token,
            liveness_checker,
            command_line: self.command_line,
        })
    }
}
