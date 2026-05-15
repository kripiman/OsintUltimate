use std::sync::Arc;
use tokio::sync::mpsc;
use crate::models::TargetHost;
use crate::plugins::ScannerPlugin;
use crate::core::orchestrator::{Orchestrator, OrchestratorConfig};
use crate::utils::executor::{StealthExecutor, ExecutorMode};

pub fn spawn_scanning_stage<M: ExecutorMode>(
    scan_rx: mpsc::Receiver<TargetHost>,
    sink_tx: mpsc::Sender<TargetHost>,
    liveness_tx: mpsc::Sender<TargetHost>,
    plugins: Arc<Vec<Box<dyn ScannerPlugin>>>,
    concurrency: usize,
    layer_policy: crate::core::capability_layer::ScanLayerPolicy,
    approval_gate: Arc<crate::core::approval_gate::ApprovalGate>,
    blackarch_bridge: Arc<crate::core::blackarch::BlackArchBridge>,
    memory_monitor: Arc<crate::utils::memory_monitor::MemoryMonitor>,
    sandbox: Arc<crate::core::sandbox::SandboxDispatcher>,
    policy: Arc<dyn crate::core::policy::PolicyProvider>,
    executor: Arc<StealthExecutor<M>>,
    strict_scope: bool,
    db_pool: Option<sqlx::PgPool>,
    current_scan_id: Option<i64>,
    swarm_mode: bool,
    ai_router: Option<Arc<crate::core::ai::TieredAIRouter>>,
    max_tokens: u32,
    proxy_manager: Option<Arc<crate::utils::proxy::ProxyManager>>,
    shutdown_token: tokio_util::sync::CancellationToken,
    dashboard_tx: Option<tokio::sync::broadcast::Sender<crate::models::Finding>>,
    dashboard_targets: Option<Arc<dashmap::DashMap<String, TargetHost>>>,
    #[cfg(feature = "sovereign")] sliver_ca: Option<String>,
    #[cfg(feature = "sovereign")] sliver_cert: Option<String>,
    #[cfg(feature = "sovereign")] sliver_key: Option<String>,
    #[cfg(feature = "sovereign")] sliver_addr: Option<String>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut orchestrator = Orchestrator::new(OrchestratorConfig {
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
            db_pool,
            current_scan_id,
            inventory: None,
            #[cfg(feature = "sovereign")] sliver_ca_path: sliver_ca,
            #[cfg(feature = "sovereign")] sliver_cert_path: sliver_cert,
            #[cfg(feature = "sovereign")] sliver_key_path: sliver_key,
            #[cfg(feature = "sovereign")] sliver_server_addr: sliver_addr,
        });

        if let (Some(tx), Some(targets)) = (dashboard_tx, dashboard_targets) {
            orchestrator.with_dashboard_preconfigured(tx, targets);
        }

        if swarm_mode {
            if let Some(router) = ai_router {
                orchestrator = orchestrator.with_swarm_mode(true, max_tokens, router, proxy_manager);
            }
        }
        orchestrator.run(scan_rx, sink_tx, shutdown_token).await;
    })
}
