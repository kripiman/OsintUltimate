use crate::core::orchestrator::Orchestrator;
use crate::utils::executor::{StealthExecutor, ExecutorMode};
use crate::plugins::{DiscoveryPlugin, ScannerPlugin};
use crate::models::{TargetHost, Finding, Category, Severity, TargetStatus, ScanMetadata};
use crate::core::sink::DataSink;
use crate::utils::{LivenessChecker, JitterSleep};
use crate::utils::liveness::is_safe_ip;
use crate::core::capability_layer::ScanLayerPolicy;
use crate::core::approval_gate::ApprovalGate;
use crate::core::filter::FalsePositiveFilter;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use serde_json::json;
use anyhow::{Result, Context};
use tokio::sync::mpsc;
use futures::StreamExt;
use bloomfilter::Bloom;

pub struct Pipeline<M: ExecutorMode = crate::utils::executor::GhostMode> {
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
    executor: Arc<StealthExecutor<M>>,
    strict_scope: bool,
}

impl<M: ExecutorMode> Pipeline<M> {
    pub fn builder() -> PipelineBuilder<M> {
        PipelineBuilder::new()
    }

    pub fn new_minimal(
        plugins: Arc<Vec<Box<dyn ScannerPlugin>>>, 
        sandbox: Arc<crate::core::sandbox::SandboxDispatcher>,
        policy: Option<Arc<dyn crate::core::policy::PolicyProvider>>,
        memory_monitor: Option<Arc<crate::utils::memory_monitor::MemoryMonitor>>,
    ) -> Self {
        let monitor = memory_monitor.unwrap_or_else(|| Arc::new(crate::utils::memory_monitor::MemoryMonitor::new(100, 200)));
        let policy = policy.unwrap_or_else(|| Arc::new(crate::core::policy::StaticPolicy::new()));
        
        // We don't really need the builder if we are just constructing the struct, 
        // especially since plugins cloning is complex.
        
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
            memory_monitor: monitor,
            dashboard_tx: None,
            dashboard_targets: None,
            swarm_mode: false,
            max_tokens: 0,
            ai_router: None,
            sandbox,
            proxy_manager: None,
            policy: policy.clone(),
            executor: Arc::new(crate::utils::executor::StealthExecutor::<M>::new(
                policy, 
                None, 
                false,
            )),
            strict_scope: false,
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
        let (sink_tx, sink_rx) = mpsc::channel::<TargetHost>(1024);

        let mut handles = Vec::new();
        
        // --- STAGE 1: Discovery ---
        handles.push(self.spawn_discovery_stage(osint_rx, liveness_tx.clone()));
        
        let osint_token = self.shutdown_token.clone();
        tokio::spawn(async move {
            while let Some(t) = targets.next().await {
                if osint_token.is_cancelled() { break; }
                if osint_tx.send(t).await.is_err() { break; }
            }
        });

        // --- STAGE 2: Liveness ---
        handles.push(self.spawn_liveness_stage(liveness_rx, scan_tx.clone(), sink_tx.clone()));
        drop(scan_tx);

        // --- STAGE 3: Scanning ---
        handles.push(self.spawn_scanning_stage(scan_rx, sink_tx.clone(), liveness_tx.clone()));
        drop(sink_tx);
        drop(liveness_tx);

        // --- STAGE 4: Sink (v4 Lock-Free) ---
        self.run_sink_stage(sink, sink_rx).await?;
        
        Ok(())
    }

    fn spawn_discovery_stage(&self, mut rx: mpsc::Receiver<TargetHost>, liveness_tx: mpsc::Sender<TargetHost>) -> tokio::task::JoinHandle<()> {
        let mut seen_domains = Bloom::new_for_fp_rate(1_000_000, 0.01);
        let discovery_token = self.shutdown_token.clone();
        let discovery_plugins = self.discovery_plugins.clone();
        let jitter = self.jitter.clone();
        
        tokio::spawn(async move {
            while let Some(mut target) = rx.recv().await {
                if discovery_token.is_cancelled() { break; }

                if target.target_type == crate::models::TargetType::Mobile || target.target_type == crate::models::TargetType::Container {
                    let _ = liveness_tx.send(target).await;
                    continue;
                }
                
                if let Some(ref j) = jitter {
                    j.apply().await;
                }

                if seen_domains.check(&target.host) { continue; }
                seen_domains.set(&target.host);

                // Forward original target to liveness check
                let _ = liveness_tx.send(target.clone()).await;

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
            file_path: None,
                                    user: None,
                                    findings: Arc::new(Vec::new()),
                                    tool_suggestions: Arc::new(Vec::new()),
                                    tactical_context: Arc::new(serde_json::json!({})),
                                    extra_data: Arc::new(serde_json::json!({})),
                                    version: 0,
                                    skip_heavy_scan: false,
                                }).await;
                            }
                        }
                    }
                }
                let _ = liveness_tx.send(target).await;
            }
        })
    }

    fn spawn_liveness_stage(&self, mut rx: mpsc::Receiver<TargetHost>, scan_tx: mpsc::Sender<TargetHost>, sink_tx: mpsc::Sender<TargetHost>) -> tokio::task::JoinHandle<()> {
        let liveness_checker = self.liveness_checker.clone();
        let liveness_token = self.shutdown_token.clone();
        let liveness_concurrency = self.concurrency;
        
        let stream_token = liveness_token.clone();
        tokio::spawn(async move {
            let stream = async_stream::stream! {
                while let Some(t) = rx.recv().await { yield t; if stream_token.is_cancelled() { break; } }
            };
            tokio::pin!(stream);
            stream.for_each_concurrent(liveness_concurrency, move |mut target| {
                let checker = liveness_checker.clone(); 
                let scan_tx = scan_tx.clone(); 
                let sink_tx = sink_tx.clone(); 
                let token = liveness_token.clone();
                async move {
                    if target.target_type == crate::models::TargetType::Mobile || target.target_type == crate::models::TargetType::Container {
                        let _ = scan_tx.send(target).await;
                        return;
                    }

                    if let Some(ip) = tokio::select! { res = checker.is_live(&target.host) => res, _ = token.cancelled() => return } {
                        if !is_safe_ip(&ip) { 
                            warn!("🛡️ V13: Blocked unsafe IP {} for host {}", ip, target.host);
                            target.status = TargetStatus::Dead; 
                            let _ = sink_tx.send(target).await; 
                            return; 
                        }
                        target.ip = Some(ip.to_string()); 
                        target.resolved_ip = Some(ip.to_string());

                        // CDN GATING (V14.5): Auto-detect CDN/WAF to optimize scan resources
                        let cdn_checker = crate::plugins::reconnaissance::active::cdncheck::CdnCheckScanner::new();
                        if let Ok(true) = cdn_checker.is_cdn(&ip.to_string()).await {
                             info!("🛡️ CDN GATE: Target {} detected behind CDN/Cloud. Scans will be filtered.", target.host);
                             target.skip_heavy_scan = true;
                        }

                        let _ = scan_tx.send(target).await;
                    } else { 
                        warn!("⚠️ V13: Resolution failed for host {}. Aborting scan to prevent DNS Rebinding.", target.host);
                        target.status = TargetStatus::Dead; 
                        let _ = sink_tx.send(target).await; 
                    }
                }
            }).await;
        })
    }

    fn spawn_scanning_stage(&self, scan_rx: mpsc::Receiver<TargetHost>, sink_tx: mpsc::Sender<TargetHost>, liveness_tx: mpsc::Sender<TargetHost>) -> tokio::task::JoinHandle<()> {
        let plugins = self.plugins.clone();
        let concurrency = self.concurrency;
        let layer_policy = self.layer_policy;
        let approval_gate = self.approval_gate.clone();
        let blackarch_bridge = self.blackarch_bridge.clone();
        let scan_token = self.shutdown_token.clone();
        let memory_monitor = self.memory_monitor.clone();
        let sandbox = self.sandbox.clone();
        let policy = self.policy.clone();
        let executor = self.executor.clone();
        let dashboard_tx = self.dashboard_tx.clone();
        let dashboard_targets = self.dashboard_targets.clone();
        let swarm_mode = self.swarm_mode;
        let ai_router = self.ai_router.clone();
        let max_tokens = self.max_tokens;
        let proxy_manager = self.proxy_manager.clone();
        let strict_scope = self.strict_scope;

        tokio::spawn(async move {
            let mut orchestrator = Orchestrator::new(crate::core::orchestrator::OrchestratorConfig {
                plugins,
                concurrency,
                layer_policy,
                approval_gate,
                blackarch_bridge,
                memory_monitor,
                sandbox,
                policy,
                executor,
                strict_scope,
                feedback_tx: Some(liveness_tx),
            });
            if let (Some(tx), Some(targets)) = (dashboard_tx, dashboard_targets) {
                orchestrator.with_dashboard_preconfigured(tx, targets);
            }
            if swarm_mode {
                if let Some(router) = ai_router {
                    orchestrator = orchestrator.with_swarm_mode(true, max_tokens, router, proxy_manager);
                }
            }
            orchestrator.run(scan_rx, sink_tx, scan_token).await;
        })
    }

    async fn run_sink_stage(&self, final_sink: Box<dyn DataSink>, mut sink_rx: mpsc::Receiver<TargetHost>) -> Result<()> {
        let v4_sink = Arc::new(crate::core::lock_free_sink::LockFreeResultSink::new());
        let fp_filter = self.fp_filter.clone();
        
        v4_sink.start_worker(final_sink);

        while let Some(mut target) = sink_rx.recv().await {
            Self::enrich_target_findings_static(&mut target).await;
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
        
        // V14.2: We need a copy of the self-context for enrichment if needed, 
        // but here we'll use the static manager for simplicity.
        let handle = tokio::spawn(async move {
            while let Some(mut target) = rx.recv().await {
                // V14.2 ENRICHMENT: Local Cache lookup
                Self::enrich_target_findings_static(&mut target).await;

                Arc::make_mut(&mut target.findings).retain(|f| fp_filter.evaluate(f));
                let _ = sink.write(&target).await;
            }
            let _ = sink.close().await;
        });

        Ok((tx, handle))
    }


    /// Static version of enrichment to avoid lifetime issues in background tasks.
    async fn enrich_target_findings_static(target: &mut TargetHost) {
        let manager = match crate::utils::cve_cache::CveCacheManager::global() {
            Some(m) => m,
            None => return,
        };

        let re = regex::Regex::new(r"CVE-\d{4}-\d{4,}").unwrap();
        let findings_mut = Arc::make_mut(&mut target.findings);

        for finding in findings_mut.iter_mut() {
            // Try to find CVE ID in title, id or description
            let cve_id = if let Some(cap) = re.captures(&finding.id) {
                Some(cap[0].to_uppercase())
            } else { re.captures(&finding.title).map(|cap| cap[0].to_uppercase()) };

            if let Some(id) = cve_id {
                if let Ok(Some(meta)) = manager.get_or_fetch_cve(&id).await {
                    info!("✨ V14.2 ENRICH: Enriched finding {} with cached metadata for {}", finding.core.id, id);
                    if finding.core.tactical_path.is_none() {
                        finding.core.tactical_path = meta.tactical_path;
                    }
                    if let Some(score) = meta.cvss_score {
                        finding.enrichment.cvss_score = Some(score);
                    }
                    for r in meta.references {
                        if !finding.enrichment.references.contains(&r) {
                            finding.enrichment.references.push(r);
                        }
                    }
                }
            }
        }
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
        let orchestrator = Orchestrator::new(crate::core::orchestrator::OrchestratorConfig {
            plugins: self.plugins.clone(),
            concurrency: self.concurrency,
            layer_policy: self.layer_policy,
            approval_gate: self.approval_gate.clone(),
            blackarch_bridge: self.blackarch_bridge.clone(),
            memory_monitor: self.memory_monitor.clone(),
            sandbox: self.sandbox.clone(),
            policy: self.policy.clone(),
            executor: self.executor.clone(),
            strict_scope: self.strict_scope,
            feedback_tx: None,
        });
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


pub struct PipelineBuilder<M: ExecutorMode = crate::utils::executor::GhostMode> {
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
    executor: Option<Arc<crate::utils::executor::StealthExecutor<M>>>,
    strict_scope: bool,
}

impl<M: ExecutorMode> Default for PipelineBuilder<M> { fn default() -> Self { Self::new() } }

impl<M: ExecutorMode> PipelineBuilder<M> {
    pub fn new() -> Self {
        Self {
            concurrency: 10,
            discovery_plugins: Vec::new(),
            plugins: Vec::new(),
            sink: None,
            shutdown_token: CancellationToken::new(),
            liveness_checker: None,
            command_line: "Mimikri".to_string(),
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
            strict_scope: false,
        }
    }

    pub fn with_policy(mut self, policy: Arc<dyn crate::core::policy::PolicyProvider>) -> Self {
        self.policy = Some(policy);
        self
    }

    pub fn with_executor(mut self, executor: Arc<crate::utils::executor::StealthExecutor<M>>) -> Self {
        self.executor = Some(executor);
        self
    }

    pub fn with_swarm(mut self, enabled: bool, max_tokens: u32, router: Arc<crate::core::ai::TieredAIRouter>, proxy_manager: Option<Arc<crate::utils::proxy::ProxyManager>>, executor: Arc<crate::utils::executor::StealthExecutor<M>>, policy: Arc<dyn crate::core::policy::PolicyProvider>) -> Self {
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
    pub fn strict_scope(mut self, s: bool) -> Self { self.strict_scope = s; self }

    pub fn build(self) -> Result<Pipeline<M>> {
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
            strict_scope: self.strict_scope,
        })
    }
}
