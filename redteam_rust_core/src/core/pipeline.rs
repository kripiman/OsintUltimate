use crate::core::orchestrator::Orchestrator;
use crate::core::sink::DataSink;
use crate::models::{TargetHost, TargetStatus, Finding, Category, Severity, ScanMetadata};
use crate::plugins::{ScannerPlugin, DiscoveryPlugin};
use crate::utils::{LivenessChecker, JitterSleep};
use crate::utils::liveness::is_safe_ip;
use crate::core::capability_layer::ScanLayerPolicy;
use crate::core::approval_gate::ApprovalGate;
use crate::core::filter::FalsePositiveFilter;
use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::info;
use futures::stream::StreamExt;
use serde_json::json;
use bloomfilter::Bloom;

pub struct Pipeline {
    concurrency: usize,
    discovery_plugins: Arc<Vec<Box<dyn DiscoveryPlugin>>>,
    plugins: Arc<Vec<Box<dyn ScannerPlugin>>>,
    sink: Option<Box<dyn DataSink>>,
    shutdown_token: CancellationToken,
    liveness_checker: LivenessChecker,
    command_line: String,
    policy: ScanLayerPolicy,
    approval_gate: Arc<ApprovalGate>,
    blackarch_bridge: Arc<crate::core::blackarch::BlackArchBridge>,
    jitter: Option<JitterSleep>,
    fp_filter: Arc<FalsePositiveFilter>,
    memory_monitor: Arc<crate::utils::memory_monitor::MemoryMonitor>,
}

impl Pipeline {
    pub fn builder() -> PipelineBuilder {
        PipelineBuilder::new()
    }

    /// Runs the 4-stage pipeline: Discovery -> Liveness -> Scanning -> Sink
    pub async fn run(mut self, targets: Vec<TargetHost>) -> Result<()> {
        info!("🚀 Starting Pipeline with {} plugins...", self.plugins.len());
        
        let mut sink = self.sink.take().context("Pipeline: Sink already taken")?;
        sink.write_metadata(&ScanMetadata::new(&self.command_line)).await?;

        let channel_size = (self.concurrency * 2).clamp(4, 32);
        
        let (osint_tx, osint_rx) = mpsc::channel::<TargetHost>(channel_size);
        let (liveness_tx, liveness_rx) = mpsc::channel::<TargetHost>(channel_size);
        let (scan_tx, scan_rx) = mpsc::channel::<TargetHost>(channel_size);
        let (sink_tx, mut sink_rx) = mpsc::channel::<TargetHost>(channel_size);

        let mut handles = Vec::new();
        
        // --- STAGE 1: Discovery ---
        let mut seen_domains = Bloom::new_for_fp_rate(1_000_000, 0.01);
        let discovery_token = self.shutdown_token.clone();
        let discovery_plugins = self.discovery_plugins.clone();
        
        handles.push(tokio::spawn(async move {
            let mut rx = osint_rx;
            while let Some(mut target) = rx.recv().await {
                if discovery_token.is_cancelled() { break; }
                
                // Apply jitter if configured for stealth scanning
                if let Some(ref jitter) = self.jitter {
                    jitter.apply().await;
                }

                if seen_domains.check(&target.host) { continue; }
                seen_domains.set(&target.host);

                let mut join_set = tokio::task::JoinSet::new();
                for i in 0..discovery_plugins.len() {
                    let plugins_clone = discovery_plugins.clone();
                    let target_snapshot = target.clone();
                    join_set.spawn(async move {
                        let plugin = &plugins_clone[i];
                        let name = plugin.name().to_string();
                        let result = plugin.discover(&target_snapshot).await;
                        (name, result)
                    });
                }

                while let Some(join_res) = join_set.join_next().await {
                    if let Ok((name, Ok(subdomains))) = join_res {
                        for sub in subdomains {
                            if !seen_domains.check(&sub) {
                                seen_domains.set(&sub);
                                target.findings.push(Finding::new("DISCOVERED_SUBDOMAIN", Category::Recon, Severity::Info, &format!("Discovered via {}: {}", name, sub), json!({ "subdomain": sub, "source": name })));
                                let _ = liveness_tx.send(TargetHost { 
                                    host: sub, 
                                    ip: None, 
                                    status: TargetStatus::Pending, 
                                    target_type: crate::models::TargetType::Web,
                                    findings: Vec::new(),
                                    tool_suggestions: Vec::new(),
                                    tactical_context: serde_json::json!({}),
                                    extra_data: serde_json::json!({}),
                                }).await;
                            }
                        }
                    }
                }
                let _ = liveness_tx.send(target).await;
            }
        }));

        for t in targets { let _ = osint_tx.send(t).await; }
        drop(osint_tx);

        // --- STAGE 2: Liveness ---
        let liveness_checker = self.liveness_checker.clone();
        let liveness_token = self.shutdown_token.clone();
        let scan_tx_clone = scan_tx.clone();
        let sink_tx_err = sink_tx.clone();
        let liveness_concurrency = self.concurrency;
        drop(scan_tx);

        let stream_token = liveness_token.clone();
        handles.push(tokio::spawn(async move {
            let mut rx = liveness_rx;
            let stream = async_stream::stream! {
                while let Some(t) = rx.recv().await { yield t; if stream_token.is_cancelled() { break; } }
            };
            tokio::pin!(stream);
            stream.for_each_concurrent(liveness_concurrency, move |mut target| {
                let checker = liveness_checker.clone(); let scan_tx = scan_tx_clone.clone(); let sink_tx = sink_tx_err.clone(); let token = liveness_token.clone();
                async move {
                    if let Some(ip) = tokio::select! { res = checker.is_live(&target.host) => res, _ = token.cancelled() => return } {
                        if !is_safe_ip(&ip) { target.status = TargetStatus::Dead; let _ = sink_tx.send(target).await; return; }
                        target.ip = Some(ip.to_string()); let _ = scan_tx.send(target).await;
                    } else { target.status = TargetStatus::Dead; let _ = sink_tx.send(target).await; }
                }
            }).await;
        }));

        // --- STAGE 3: Scanning ---
        let plugins = self.plugins.clone();
        let concurrency = self.concurrency;
        let policy = self.policy;
        let approval_gate = self.approval_gate.clone();
        let blackarch_bridge = self.blackarch_bridge.clone();
        let scan_rx = scan_rx;
        let sink_tx_stage3 = sink_tx.clone();
        let scan_token = self.shutdown_token.clone();
        let memory_monitor = self.memory_monitor.clone();
        handles.push(tokio::spawn(async move {
            let orchestrator = Orchestrator::new(
                plugins, 
                concurrency,
                policy,
                approval_gate,
                blackarch_bridge,
                memory_monitor,
            );
            orchestrator.run(scan_rx, sink_tx_stage3, scan_token).await;
        }));
        drop(sink_tx);

        // --- STAGE 4: Sink ---
        let mut final_sink = sink;
        let mut final_sink_rx = sink_rx;
        let fp_filter = self.fp_filter.clone();
        handles.push(tokio::spawn(async move {
            while let Some(mut target) = final_sink_rx.recv().await {
                // Apply FalsePositiveFilter
                target.findings.retain(|f| fp_filter.evaluate(f));
                let _ = final_sink.write(&target).await;
            }
            let _ = final_sink.close().await;
        }));

        for h in handles { let _ = h.await; }
        Ok(())
    }

    /// Starts ONLY the sink stage and returns a sender. Useful for Autonomous mode.
    pub async fn start_sink_stage(&mut self) -> Result<(mpsc::Sender<TargetHost>, tokio::task::JoinHandle<()>)> {
        let mut sink = self.sink.take().context("Pipeline: Sink already taken")?;
        sink.write_metadata(&ScanMetadata::new(&self.command_line)).await?;
        
        let (tx, mut rx) = mpsc::channel(100);
        let fp_filter = self.fp_filter.clone();
        let handle = tokio::spawn(async move {
            while let Some(mut target) = rx.recv().await {
                target.findings.retain(|f| fp_filter.evaluate(f));
                let _ = final_sink.write(&target).await;
            }
            let _ = final_sink.close().await;
        });

        Ok((tx, handle))
    }

    pub async fn run_discovery(&self, target: &TargetHost, tx: mpsc::Sender<Finding>) -> Result<()> {
        info!("Pipeline: Running discovery for {}", target.host);
        let discovery_plugins = self.discovery_plugins.clone();
        let mut join_set = tokio::task::JoinSet::new();
        for i in 0..discovery_plugins.len() {
            let plugins_clone = discovery_plugins.clone(); let target_snapshot = target.clone();
            join_set.spawn(async move { (plugins_clone[i].name().to_string(), plugins_clone[i].discover(&target_snapshot).await) });
        }
        while let Some(res) = join_set.join_next().await {
            if let Ok((name, Ok(subdomains))) = res {
                for sub in subdomains { tx.send(Finding::new("DISCOVERED_SUBDOMAIN", Category::Recon, Severity::Info, &format!("via {}", name), json!({"sub":sub}))).await?; }
            }
        }
        Ok(())
    }

    pub async fn run_scanning(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        info!("Pipeline: Running active scans for {}", target.host);
        let (tx, rx) = mpsc::channel(1);
        let (out_tx, mut out_rx) = mpsc::channel(1);
        let orchestrator = Orchestrator::new(
            self.plugins.clone(), 
            self.concurrency,
            self.policy,
            self.approval_gate.clone(),
            self.blackarch_bridge.clone(),
        );
        let token = self.shutdown_token.clone();
        
        let target_clone = target.clone();
        let tx_clone = tx.clone();
        tokio::spawn(async move { let _ = tx_clone.send(target_clone).await; });
        drop(tx);

        orchestrator.run(rx, out_tx, token).await;
        
        if let Some(res) = out_rx.recv().await {
            Ok(res.findings)
        } else {
            Ok(Vec::new())
        }
    }

    pub fn get_plugin_names(&self) -> Vec<String> {
        self.plugins.iter().map(|p| p.name().to_string()).collect()
    }

    pub fn get_plugin_metadata(&self) -> Vec<crate::plugins::PluginMetadata> {
        self.plugins.iter().map(|p| p.metadata()).collect()
    }

    pub async fn run_specific_plugin(&self, plugin_name: &str, target: &TargetHost) -> Result<Vec<Finding>> {
        info!("Pipeline: Running specific plugin '{}' for {}", plugin_name, target.host);
        if let Some(plugin) = self.plugins.iter().find(|p| p.name() == plugin_name) {
            plugin.scan(target).await
        } else {
            anyhow::bail!("Plugin '{}' not found", plugin_name)
        }
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
    policy: Option<ScanLayerPolicy>,
    approval_gate: Option<Arc<ApprovalGate>>,
    jitter: Option<JitterSleep>,
    fp_filter: Option<Arc<FalsePositiveFilter>>,
    memory_monitor: Option<Arc<crate::utils::memory_monitor::MemoryMonitor>>,
}

impl Default for PipelineBuilder { fn default() -> Self { Self::new() } }

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
            policy: None,
            approval_gate: None,
            jitter: None,
            fp_filter: None,
            memory_monitor: None,
        }
    }

    pub fn with_jitter(mut self, jitter: Option<JitterSleep>) -> Self {
        self.jitter = jitter;
        self 
    }

    pub fn with_filter(mut self, filter: Arc<FalsePositiveFilter>) -> Self { self.fp_filter = Some(filter); self }

    pub fn memory_monitor(mut self, monitor: Arc<crate::utils::memory_monitor::MemoryMonitor>) -> Self { self.memory_monitor = Some(monitor); self }

    pub fn policy(mut self, policy: ScanLayerPolicy) -> Self { self.policy = Some(policy); self }
    pub fn approval_gate(mut self, gate: Arc<ApprovalGate>) -> Self { self.approval_gate = Some(gate); self }

    pub fn liveness_checker(mut self, checker: LivenessChecker) -> Self { self.liveness_checker = Some(checker); self }
    pub fn concurrency(mut self, c: usize) -> Self { self.concurrency = c; self }
    pub fn with_discovery(mut self, plugin: Box<dyn DiscoveryPlugin>) -> Self { self.discovery_plugins.push(plugin); self }
    pub fn with_plugin(mut self, plugin: Box<dyn ScannerPlugin>) -> Self { self.plugins.push(plugin); self }
    pub fn with_sink(mut self, sink: Box<dyn DataSink>) -> Self { self.sink = Some(sink); self }
    pub fn shutdown_token(mut self, token: CancellationToken) -> Self { self.shutdown_token = token; self }
    pub fn command_line(mut self, cmd: String) -> Self { self.command_line = cmd; self }

    pub fn build(self) -> Result<Pipeline> {
        let sink = self.sink.context("Pipeline requires a configured sink")?;
        let liveness_checker = self.liveness_checker.context("Pipeline requires a configured liveness checker")?;
        let policy = self.policy.unwrap_or(ScanLayerPolicy::preset_audit());
        let approval_gate = self.approval_gate.unwrap_or(Arc::new(ApprovalGate::for_red_team()));
        let blackarch_bridge = Arc::new(crate::core::blackarch::BlackArchBridge::new());

        Ok(Pipeline {
            concurrency: self.concurrency,
            discovery_plugins: Arc::new(self.discovery_plugins),
            plugins: Arc::new(self.plugins),
            sink: Some(sink),
            shutdown_token: self.shutdown_token,
            liveness_checker,
            command_line: self.command_line,
            policy,
            approval_gate,
            blackarch_bridge,
            jitter: self.jitter,
            fp_filter: self.fp_filter.unwrap_or(Arc::new(FalsePositiveFilter::default())),
            memory_monitor: self.memory_monitor.context("Pipeline requires a configured memory monitor")?,
        })
    }
}
