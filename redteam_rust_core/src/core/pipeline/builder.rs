use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use anyhow::{Result, Context};
use crate::plugins::{DiscoveryPlugin, ScannerPlugin};
use crate::models::{TargetHost, Finding};
use crate::core::sink::DataSink;
use crate::core::approval_gate::ApprovalGate;
use crate::core::capability_layer::ScanLayerPolicy;
use crate::core::filter::FalsePositiveFilter;
use crate::utils::{LivenessChecker, JitterSleep};
use crate::utils::executor::{StealthExecutor, ExecutorMode};
use super::Pipeline;

pub struct PipelineBuilder<M: ExecutorMode = crate::utils::executor::GhostMode> {
    pub concurrency: usize,
    pub discovery_plugins: Vec<Box<dyn DiscoveryPlugin>>,
    pub plugins: Vec<Box<dyn ScannerPlugin>>,
    pub sink: Option<Box<dyn DataSink>>,
    pub shutdown_token: CancellationToken,
    pub liveness_checker: Option<LivenessChecker>,
    pub command_line: String,
    pub layer_policy: Option<ScanLayerPolicy>,
    pub approval_gate: Option<Arc<ApprovalGate>>,
    pub jitter: Option<JitterSleep>,
    pub fp_filter: Option<Arc<FalsePositiveFilter>>,
    pub dashboard_tx: Option<tokio::sync::broadcast::Sender<Finding>>,
    pub dashboard_targets: Option<Arc<dashmap::DashMap<String, TargetHost>>>,
    pub swarm_mode: bool,
    pub max_tokens: u32,
    pub ai_router: Option<Arc<crate::core::ai::TieredAIRouter>>,
    pub sandbox: Option<Arc<crate::core::sandbox::SandboxDispatcher>>,
    pub memory_monitor: Option<Arc<crate::utils::memory_monitor::MemoryMonitor>>,
    pub proxy_manager: Option<Arc<crate::utils::proxy::ProxyManager>>,
    pub policy: Option<Arc<dyn crate::core::policy::PolicyProvider>>,
    pub executor: Option<Arc<StealthExecutor<M>>>,
    pub strict_scope: bool,
    #[cfg(feature = "sovereign")] pub sliver_ca_path: Option<String>,
    #[cfg(feature = "sovereign")] pub sliver_cert_path: Option<String>,
    #[cfg(feature = "sovereign")] pub sliver_key_path: Option<String>,
    #[cfg(feature = "sovereign")] pub sliver_server_addr: Option<String>,
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
            #[cfg(feature = "sovereign")] sliver_ca_path: None,
            #[cfg(feature = "sovereign")] sliver_cert_path: None,
            #[cfg(feature = "sovereign")] sliver_key_path: None,
            #[cfg(feature = "sovereign")] sliver_server_addr: None,
        }
    }

    pub fn with_policy(mut self, policy: Arc<dyn crate::core::policy::PolicyProvider>) -> Self {
        self.policy = Some(policy);
        self
    }

    pub fn with_executor(mut self, executor: Arc<StealthExecutor<M>>) -> Self {
        self.executor = Some(executor);
        self
    }

    pub fn with_swarm(mut self, enabled: bool, max_tokens: u32, router: Arc<crate::core::ai::TieredAIRouter>, proxy_manager: Option<Arc<crate::utils::proxy::ProxyManager>>, executor: Arc<StealthExecutor<M>>, policy: Arc<dyn crate::core::policy::PolicyProvider>) -> Self {
        self.swarm_mode = enabled;
        self.max_tokens = max_tokens;
        self.ai_router = Some(router);
        self.proxy_manager = proxy_manager;
        self.executor = Some(executor);
        self.policy = Some(policy);
        self
    }

    pub fn with_dashboard(mut self, tx: tokio::sync::broadcast::Sender<Finding>, targets: Arc<dashmap::DashMap<String, TargetHost>>) -> Self {
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

    #[cfg(feature = "sovereign")]
    pub fn with_sliver(mut self, ca: Option<String>, cert: Option<String>, key: Option<String>, addr: Option<String>) -> Self {
        self.sliver_ca_path = ca;
        self.sliver_cert_path = cert;
        self.sliver_key_path = key;
        self.sliver_server_addr = addr;
        self
    }

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
            #[cfg(feature = "sovereign")] sliver_ca_path: self.sliver_ca_path,
            #[cfg(feature = "sovereign")] sliver_cert_path: self.sliver_cert_path,
            #[cfg(feature = "sovereign")] sliver_key_path: self.sliver_key_path,
            #[cfg(feature = "sovereign")] sliver_server_addr: self.sliver_server_addr,
        })
    }
}
