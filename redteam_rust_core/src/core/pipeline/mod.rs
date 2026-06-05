use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::info;
use anyhow::{Result, Context};
use futures::StreamExt;

use crate::plugins::{DiscoveryPlugin, ScannerPlugin};
use crate::models::{TargetHost, Finding, Category, Severity, ScanMetadata};
use crate::core::sink::DataSink;
use crate::core::capability_layer::ScanLayerPolicy;
use crate::core::approval_gate::ApprovalGate;
use crate::core::filter::FalsePositiveFilter;
use crate::utils::{LivenessChecker, JitterSleep};
use crate::utils::executor::{StealthExecutor, ExecutorMode};
use crate::core::orchestrator::OrchestratorConfig;

pub mod builder;
pub mod stages;
pub mod enrichment;

pub use builder::PipelineBuilder;

pub struct Pipeline<M: ExecutorMode = crate::utils::executor::GhostMode> {
    pub(crate) concurrency: usize,
    pub(crate) discovery_plugins: Arc<Vec<Box<dyn DiscoveryPlugin>>>,
    pub(crate) plugins: Arc<Vec<Box<dyn ScannerPlugin>>>,
    pub(crate) sink: Option<Box<dyn DataSink>>,
    pub(crate) shutdown_token: CancellationToken,
    pub(crate) liveness_checker: LivenessChecker,
    pub(crate) command_line: String,
    pub(crate) layer_policy: ScanLayerPolicy,
    pub(crate) approval_gate: Arc<ApprovalGate>,
    pub(crate) blackarch_bridge: Arc<crate::core::blackarch::BlackArchBridge>,
    pub(crate) jitter: Option<JitterSleep>,
    pub(crate) fp_filter: Arc<FalsePositiveFilter>,
    pub(crate) memory_monitor: Arc<crate::utils::memory_monitor::MemoryMonitor>,
    pub(crate) dashboard_tx: Option<tokio::sync::broadcast::Sender<Finding>>,
    pub(crate) dashboard_targets: Option<Arc<dashmap::DashMap<String, TargetHost>>>,
    pub(crate) swarm_mode: bool,
    pub(crate) max_tokens: u32,
    pub(crate) ai_router: Option<Arc<crate::core::ai::TieredAIRouter>>,
    pub(crate) sandbox: Arc<crate::core::sandbox::SandboxDispatcher>,
    pub(crate) proxy_manager: Option<Arc<crate::utils::proxy::ProxyManager>>,
    pub(crate) policy: Arc<dyn crate::core::policy::PolicyProvider>,
    pub(crate) executor: Arc<StealthExecutor<M>>,
    pub(crate) strict_scope: bool,
    #[cfg(feature = "sovereign")] pub(crate) sliver_ca_path: Option<String>,
    #[cfg(feature = "sovereign")] pub(crate) sliver_cert_path: Option<String>,
    #[cfg(feature = "sovereign")] pub(crate) sliver_key_path: Option<String>,
    #[cfg(feature = "sovereign")] pub(crate) sliver_server_addr: Option<String>,
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
        
        Self {
            concurrency: 1,
            discovery_plugins: Arc::new(Vec::new()),
            plugins,
            sink: None, 
            shutdown_token: CancellationToken::new(),
            liveness_checker: LivenessChecker::new(None, false),
            command_line: "minimal".to_string(),
            layer_policy: ScanLayerPolicy::preset_audit(),
            approval_gate: Arc::new(ApprovalGate::for_red_team()),
            blackarch_bridge: Arc::new(crate::core::blackarch::BlackArchBridge::new()),
            jitter: None,
            fp_filter: Arc::new(FalsePositiveFilter::default()),
            memory_monitor: monitor,
            dashboard_tx: None,
            dashboard_targets: None,
            swarm_mode: false,
            max_tokens: 0,
            ai_router: None,
            sandbox,
            proxy_manager: None,
            policy: policy.clone(),
            executor: Arc::new(StealthExecutor::<M>::new(policy, None, false)),
            strict_scope: false,
            #[cfg(feature = "sovereign")] sliver_ca_path: None,
            #[cfg(feature = "sovereign")] sliver_cert_path: None,
            #[cfg(feature = "sovereign")] sliver_key_path: None,
            #[cfg(feature = "sovereign")] sliver_server_addr: None,
        }
    }

    pub async fn run(mut self, mut targets: futures::stream::BoxStream<'static, TargetHost>) -> Result<()> {
        info!("🚀 Starting Pipeline with {} plugins...", self.plugins.len());
        
        let mut sink = self.sink.take().context("Pipeline: Sink already taken")?;
        sink.write_metadata(&ScanMetadata::new(&self.command_line)).await?;

        let channel_size = (self.concurrency * 2).clamp(4, 32);
        let (osint_tx, osint_rx) = mpsc::channel(channel_size);
        let (liveness_tx, liveness_rx) = mpsc::channel(channel_size);
        let (scan_tx, scan_rx) = mpsc::channel(channel_size);
        // ARCH-11 Fix: Buffer 1024 is chosen based on 24h scan throughput estimates (~100k findings/day)
        // providing ~15min of backpressure relief at peak ingest.
        let (sink_tx, sink_rx) = mpsc::channel(1024);

        // Discovery
        stages::discovery::spawn_discovery_stage(
            osint_rx, liveness_tx.clone(), self.discovery_plugins.clone(), self.jitter.clone(), self.shutdown_token.clone()
        );
        
        let osint_token = self.shutdown_token.clone();
        tokio::spawn(async move {
            while let Some(t) = targets.next().await {
                if osint_token.is_cancelled() { break; }
                if osint_tx.send(t).await.is_err() { break; }
            }
        });

        // Liveness
        stages::liveness::spawn_liveness_stage(
            liveness_rx, scan_tx.clone(), sink_tx.clone(), self.liveness_checker.clone(), self.concurrency, self.shutdown_token.clone()
        );
        drop(scan_tx);

        let db_pool = sink.get_db_pool();
        let current_scan_id = sink.get_scan_id();

        // Scanning
        let orchestrator_config = OrchestratorConfig {
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
            feedback_tx: Some(liveness_tx.clone()),
            db_pool,
            current_scan_id,
            inventory: None,
            #[cfg(feature = "sovereign")]
            sliver_ca_path: self.sliver_ca_path.clone(),
            #[cfg(feature = "sovereign")]
            sliver_cert_path: self.sliver_cert_path.clone(),
            #[cfg(feature = "sovereign")]
            sliver_key_path: self.sliver_key_path.clone(),
            #[cfg(feature = "sovereign")]
            sliver_server_addr: self.sliver_server_addr.clone(),
        };

        let swarm_config = stages::scanning::ScanningStageSwarm {
            swarm_mode: self.swarm_mode,
            ai_router: self.ai_router.clone(),
            max_tokens: self.max_tokens,
            proxy_manager: self.proxy_manager.clone(),
        };

        let dashboard_config = stages::scanning::ScanningStageDashboard {
            dashboard_tx: self.dashboard_tx.clone(),
            dashboard_targets: self.dashboard_targets.clone(),
        };

        stages::scanning::spawn_scanning_stage(
            scan_rx,
            sink_tx.clone(),
            self.shutdown_token.clone(),
            orchestrator_config,
            swarm_config,
            dashboard_config,
        );
        drop(sink_tx);
        drop(liveness_tx);

        // Sink
        stages::sink::run_sink_stage(sink, sink_rx, self.fp_filter.clone()).await?;
        
        Ok(())
    }

    pub async fn start_sink_stage(&mut self) -> Result<(mpsc::Sender<TargetHost>, tokio::task::JoinHandle<()>)> {
        let sink = self.sink.take().context("Pipeline: Sink already taken")?;
        stages::sink::start_sink_stage(sink, &self.command_line, self.fp_filter.clone()).await
    }

    pub async fn run_discovery(&self, target: &TargetHost, tx: mpsc::Sender<Finding>) -> Result<()> {
        info!("Pipeline: Running discovery for {}", target.host);
        let mut join_set = tokio::task::JoinSet::new();
        for i in 0..self.discovery_plugins.len() {
            let plugins_clone = self.discovery_plugins.clone();
            let target_snapshot = target.clone();
            join_set.spawn(async move { (plugins_clone[i].name().to_string(), plugins_clone[i].discover(&target_snapshot).await) });
        }
        while let Some(res) = join_set.join_next().await {
            if let Ok((name, Ok(subdomains))) = res {
                for sub in subdomains { 
                    tx.send(Finding::new("DISCOVERED_SUBDOMAIN", Category::Recon, Severity::Info, &format!("via {}", name), serde_json::json!({"sub":sub}))).await?; 
                }
            }
        }
        Ok(())
    }

    pub async fn run_scanning(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        info!("Pipeline: Running active scans for {}", target.host);
        let (tx, rx) = mpsc::channel(1);
        let (out_tx, mut out_rx) = mpsc::channel(1);
        
        let mut orchestrator = crate::core::orchestrator::Orchestrator::new(crate::core::orchestrator::OrchestratorConfig {
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
            db_pool: None,
            current_scan_id: None,
            inventory: None,
            #[cfg(feature = "sovereign")] sliver_ca_path: self.sliver_ca_path.clone(),
            #[cfg(feature = "sovereign")] sliver_cert_path: self.sliver_cert_path.clone(),
            #[cfg(feature = "sovereign")] sliver_key_path: self.sliver_key_path.clone(),
            #[cfg(feature = "sovereign")] sliver_server_addr: self.sliver_server_addr.clone(),
        });

        if self.swarm_mode {
            if let Some(router) = self.ai_router.clone() {
                orchestrator = orchestrator.with_swarm_mode(true, self.max_tokens, router, self.proxy_manager.clone());
            }
        }
        
        let target_clone = target.clone();
        tokio::spawn(async move { let _ = tx.send(target_clone).await; });
        orchestrator.run(rx, out_tx, self.shutdown_token.clone()).await;
        
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
        if let Some(plugin) = self.plugins.iter().find(|p| p.name() == plugin_name) {
            plugin.scan(target).await
        } else {
            anyhow::bail!("Plugin '{}' not found", plugin_name)
        }
    }

    pub fn get_c2_operators(&self) -> Vec<&dyn crate::core::orchestrator::c2::C2Operator> {
        self.plugins.iter().filter_map(|p| p.as_c2_operator()).collect()
    }

    pub fn get_plugins_ref(&self) -> &[Box<dyn ScannerPlugin>] {
        &self.plugins
    }

    pub fn get_layer_policy(&self) -> &ScanLayerPolicy {
        &self.layer_policy
    }
}
