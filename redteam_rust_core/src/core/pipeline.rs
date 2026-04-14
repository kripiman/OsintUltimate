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
use tracing::{info, warn};
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
    layer_policy: ScanLayerPolicy,
    approval_gate: Arc<ApprovalGate>,
    blackarch_bridge: Arc<crate::core::blackarch::BlackArchBridge>,
    jitter: Option<JitterSleep>,
    fp_filter: Arc<FalsePositiveFilter>,
    memory_monitor: Arc<crate::utils::memory_monitor::MemoryMonitor>,
    dashboard_tx: Option<tokio::sync::broadcast::Sender<crate::models::Finding>>,
    dashboard_targets: Option<Arc<dashmap::DashMap<String, TargetHost>>>,
    swarm_mode: bool,
    max_tokens: u32,
    ai_router: Option<Arc<crate::core::ai::TieredAIRouter>>,
    sandbox: Arc<crate::core::sandbox::SandboxDispatcher>,
    proxy_manager: Option<Arc<crate::utils::proxy::ProxyManager>>,
    policy: Arc<dyn crate::core::policy::PolicyProvider>,
    executor: Arc<crate::utils::executor::StealthExecutor>,
}
impl Pipeline {
    pub fn builder() -> PipelineBuilder {
        PipelineBuilder::new()
    }

    pub fn new_minimal(plugins: Arc<Vec<Box<dyn ScannerPlugin>>>, sandbox: Arc<crate::core::sandbox::SandboxDispatcher>) -> Self {
        Self {
            concurrency: 1,
            discovery_plugins: Arc::new(Vec::new()),
            plugins,
            sink: None, 
            shutdown_token: tokio_util::sync::CancellationToken::new(),
            liveness_checker: crate::utils::LivenessChecker::new(None, false),
            command_line: "minimal".to_string(),
            layer_policy: crate::core::capability_layer::ScanLayerPolicy::preset_audit(),
            approval_gate: Arc::new(crate::core::approval_gate::ApprovalGate::for_red_team()),
            blackarch_bridge: Arc::new(crate::core::blackarch::BlackArchBridge::new()),
            jitter: None,
            fp_filter: Arc::new(crate::core::filter::FalsePositiveFilter::default()),
            memory_monitor: Arc::new(crate::utils::memory_monitor::MemoryMonitor::new(100, 200)),
            dashboard_tx: None,
            dashboard_targets: None,
            swarm_mode: false,
            max_tokens: 0,
            ai_router: None,
            sandbox,
            proxy_manager: None,
            policy: Arc::new(crate::core::policy::StaticPolicy::new()),
            executor: Arc::new(crate::utils::executor::StealthExecutor::new(
                Arc::new(crate::core::policy::StaticPolicy::new()), 
                None, 
                false,
                None
            )),
        }
    }

    pub async fn run(mut self, mut targets: futures::stream::BoxStream<'static, TargetHost>) -> Result<()> {
        info!("🚀 Starting Pipeline with {} plugins...", self.plugins.len());
        
        let mut sink = self.sink.take().context("Pipeline: Sink already taken")?;
        sink.write_metadata(&ScanMetadata::new(&self.command_line)).await?;

        let channel_size = (self.concurrency * 2).clamp(4, 32);
        
        let (osint_tx, osint_rx) = mpsc::channel::<TargetHost>(channel_size);
        let (liveness_tx, liveness_rx) = mpsc::channel::<TargetHost>(channel_size);
        let (scan_tx, scan_rx) = mpsc::channel::<TargetHost>(channel_size);
        // ARCH-01: Decoupled Stage 4 (Sink). 1024 buffer ensures scanning isn't blocked by slow I/O.
        let (sink_tx, mut sink_rx) = mpsc::channel::<TargetHost>(1024);

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
                                Arc::make_mut(&mut target.findings).push(Finding::new("DISCOVERED_SUBDOMAIN", Category::Recon, Severity::Info, &format!("Discovered via {}: {}", name, sub), json!({ "subdomain": sub, "source": name })));
                                let _ = liveness_tx.send(TargetHost { 
                                    host: sub, 
                                    ip: None, 
                                    resolved_ip: None,
                                    status: TargetStatus::Pending, 
                                    target_type: crate::models::TargetType::Web,
                                    user: None,
                                    findings: Arc::new(Vec::new()),
                                    tool_suggestions: Arc::new(Vec::new()),
                                    tactical_context: Arc::new(serde_json::json!({})),
                                    extra_data: Arc::new(serde_json::json!({})),
                                }).await;
                            }
                        }
                    }
                }
                let _ = liveness_tx.send(target).await;
            }
        }));

        let osint_token = self.shutdown_token.clone();
        tokio::spawn(async move {
            while let Some(t) = targets.next().await {
                if osint_token.is_cancelled() { break; }
                if osint_tx.send(t).await.is_err() { break; }
            }
        });

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
                        if !is_safe_ip(&ip) { 
                            warn!("🛡️ V13: Blocked unsafe IP {} for host {}", ip, target.host);
                            target.status = TargetStatus::Dead; 
                            let _ = sink_tx.send(target).await; 
                            return; 
                        }
                        target.ip = Some(ip.to_string()); 
                        target.resolved_ip = Some(ip.to_string()); // V12: Pin IP here
                        let _ = scan_tx.send(target).await;
                    } else { 
                        warn!("⚠️ V13: Resolution failed for host {}. Aborting scan to prevent DNS Rebinding.", target.host);
                        target.status = TargetStatus::Dead; 
                        let _ = sink_tx.send(target).await; 
                    }
                }
            }).await;
        }));

        // --- STAGE 3: Scanning ---
        let plugins = self.plugins.clone();
        let concurrency = self.concurrency;
        let layer_policy = self.layer_policy;
        let approval_gate = self.approval_gate.clone();
        let blackarch_bridge = self.blackarch_bridge.clone();
        let scan_rx = scan_rx;
        let sink_tx_stage3 = sink_tx.clone();
        let scan_token = self.shutdown_token.clone();
        let memory_monitor = self.memory_monitor.clone();
        handles.push(tokio::spawn(async move {
            let mut orchestrator = Orchestrator::new(
                plugins, 
                concurrency,
                layer_policy,
                approval_gate,
                blackarch_bridge,
                memory_monitor,
                self.sandbox.clone(),
                self.policy.clone(),
                self.executor.clone(),
            );
            if let (Some(tx), Some(targets)) = (self.dashboard_tx, self.dashboard_targets) {
                orchestrator.with_dashboard_preconfigured(tx, targets);
            }
            if self.swarm_mode {
                if let Some(router) = self.ai_router.clone() {
                    orchestrator = orchestrator.with_swarm_mode(true, self.max_tokens, router, self.proxy_manager.clone());
                }
            }
            orchestrator.run(scan_rx, sink_tx_stage3, scan_token).await;
        }));
        drop(sink_tx);

        // --- STAGE 4: Sink (v4 Lock-Free) ---
        let final_sink = sink;
        let v4_sink = Arc::new(crate::core::lock_free_sink::LockFreeResultSink::new());
        let fp_filter = self.fp_filter.clone();
        
        // Start background OS thread for batched writes
        v4_sink.start_worker(final_sink);

        while let Some(mut target) = sink_rx.recv().await {
            Arc::make_mut(&mut target.findings).retain(|f| fp_filter.evaluate(f));
            v4_sink.enqueue(target);
        }
        
        v4_sink.stop();
        Ok(())
    }

    /// Starts ONLY the sink stage and returns a sender. Useful for Autonomous mode.
    pub async fn start_sink_stage(&mut self) -> Result<(mpsc::Sender<TargetHost>, tokio::task::JoinHandle<()>)> {
        let mut sink = self.sink.take().context("Pipeline: Sink already taken")?;
        sink.write_metadata(&ScanMetadata::new(&self.command_line)).await?;
        
        let (tx, mut rx) = mpsc::channel::<TargetHost>(100);
        let fp_filter = self.fp_filter.clone();
        let handle = tokio::spawn(async move {
            while let Some(mut target) = rx.recv().await {
                Arc::make_mut(&mut target.findings).retain(|f| fp_filter.evaluate(f));
                let _ = sink.write(&target).await;
            }
            let _ = sink.close().await;
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
            self.layer_policy,
            self.approval_gate.clone(),
            self.blackarch_bridge.clone(),
            self.memory_monitor.clone(),
            self.sandbox.clone(),
            self.policy.clone(),
            self.executor.clone(),
        );
        let token = self.shutdown_token.clone();
        
        let target_clone = target.clone();
        let tx_clone = tx.clone();
        tokio::spawn(async move { let _ = tx_clone.send(target_clone).await; });
        drop(tx);

        orchestrator.run(rx, out_tx, token).await;
        
        if let Some(res) = out_rx.recv().await {
            Ok((*res.findings).clone())
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

    pub fn get_c2_operators(&self) -> Vec<&dyn crate::core::c2::C2Operator> {
        self.plugins.iter()
            .filter_map(|p| p.as_c2_operator())
            .collect()
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
    layer_policy: Option<ScanLayerPolicy>,
    approval_gate: Option<Arc<ApprovalGate>>,
    jitter: Option<JitterSleep>,
    fp_filter: Option<Arc<FalsePositiveFilter>>,
    dashboard_tx: Option<tokio::sync::broadcast::Sender<crate::models::Finding>>,
    dashboard_targets: Option<Arc<dashmap::DashMap<String, TargetHost>>>,
    swarm_mode: bool,
    max_tokens: u32,
    ai_router: Option<Arc<crate::core::ai::TieredAIRouter>>,
    sandbox: Option<Arc<crate::core::sandbox::SandboxDispatcher>>,
    memory_monitor: Option<Arc<crate::utils::memory_monitor::MemoryMonitor>>,
    proxy_manager: Option<Arc<crate::utils::proxy::ProxyManager>>,
    policy: Option<Arc<dyn crate::core::policy::PolicyProvider>>,
    executor: Option<Arc<crate::utils::executor::StealthExecutor>>,
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
            layer_policy: None,
            approval_gate: None,
            jitter: None,
            fp_filter: None,
            memory_monitor: None,
            dashboard_tx: None,
            dashboard_targets: None,
            swarm_mode: false,
            max_tokens: 0,
            ai_router: None,
            sandbox: None,
            proxy_manager: None,
            policy: None,
            executor: None,
        }
    }

    pub fn with_swarm(mut self, enabled: bool, max_tokens: u32, router: Arc<crate::core::ai::TieredAIRouter>, proxy_manager: Option<Arc<crate::utils::proxy::ProxyManager>>, executor: Arc<crate::utils::executor::StealthExecutor>, policy: Arc<dyn crate::core::policy::PolicyProvider>) -> Self {
        self.swarm_mode = enabled;
        self.max_tokens = max_tokens;
        self.ai_router = Some(router);
        self.proxy_manager = proxy_manager;
        self.executor = Some(executor);
        self.policy = Some(policy);
        self
    }

    pub fn with_dashboard(mut self, tx: tokio::sync::broadcast::Sender<crate::models::Finding>, targets: Arc<dashmap::DashMap<String, TargetHost>>) -> Self {
        self.dashboard_tx = Some(tx);
        self.dashboard_targets = Some(targets);
        self
    }

    pub fn with_jitter(mut self, jitter: Option<JitterSleep>) -> Self {
        self.jitter = jitter;
        self 
    }

    pub fn with_filter(mut self, filter: Arc<FalsePositiveFilter>) -> Self { self.fp_filter = Some(filter); self }

    pub fn memory_monitor(mut self, monitor: Arc<crate::utils::memory_monitor::MemoryMonitor>) -> Self { self.memory_monitor = Some(monitor); self }

    pub fn layer_policy(mut self, policy: ScanLayerPolicy) -> Self { self.layer_policy = Some(policy); self }
    pub fn approval_gate(mut self, gate: Arc<ApprovalGate>) -> Self { self.approval_gate = Some(gate); self }

    pub fn liveness_checker(mut self, checker: LivenessChecker) -> Self { self.liveness_checker = Some(checker); self }
    pub fn concurrency(mut self, c: usize) -> Self { self.concurrency = c; self }
    pub fn with_discovery(mut self, plugin: Box<dyn DiscoveryPlugin>) -> Self { self.discovery_plugins.push(plugin); self }
    pub fn with_plugin(mut self, plugin: Box<dyn ScannerPlugin>) -> Self { self.plugins.push(plugin); self }
    pub fn with_sink(mut self, sink: Box<dyn DataSink>) -> Self { self.sink = Some(sink); self }
    pub fn shutdown_token(mut self, token: CancellationToken) -> Self { self.shutdown_token = token; self }
    pub fn command_line(mut self, cmd: String) -> Self { self.command_line = cmd; self }
    pub fn sandbox(mut self, s: Arc<crate::core::sandbox::SandboxDispatcher>) -> Self { self.sandbox = Some(s); self }

    pub fn build(self) -> Result<Pipeline> {
        let sink = self.sink.context("Pipeline requires a configured sink")?;
        let liveness_checker = self.liveness_checker.context("Pipeline requires a configured liveness checker")?;
        let layer_policy = self.layer_policy.unwrap_or(ScanLayerPolicy::preset_audit());
        let approval_gate = self.approval_gate.unwrap_or(Arc::new(ApprovalGate::for_red_team()));
        let blackarch_bridge = Arc::new(crate::core::blackarch::BlackArchBridge::new());

        let sandbox = self.sandbox.context("Pipeline requires a configured sandbox dispatcher")?;

        Ok(Pipeline {
            concurrency: self.concurrency,
            discovery_plugins: Arc::new(self.discovery_plugins),
            plugins: Arc::new(self.plugins),
            sink: Some(sink),
            shutdown_token: self.shutdown_token,
            liveness_checker,
            command_line: self.command_line,
            layer_policy,
            approval_gate,
            blackarch_bridge,
            jitter: self.jitter,
            fp_filter: self.fp_filter.unwrap_or(Arc::new(FalsePositiveFilter::default())),
            memory_monitor: self.memory_monitor.context("Pipeline requires a configured memory monitor")?,
            dashboard_tx: self.dashboard_tx,
            dashboard_targets: self.dashboard_targets,
            swarm_mode: self.swarm_mode,
            max_tokens: self.max_tokens,
            ai_router: self.ai_router,
            sandbox,
            proxy_manager: self.proxy_manager,
            policy: self.policy.context("Pipeline requires a policy provider")?,
            executor: self.executor.context("Pipeline requires an executor")?,
        })
    }
}
