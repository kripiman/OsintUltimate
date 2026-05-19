use std::sync::Arc;
use tokio::sync::mpsc;
use crate::models::TargetHost;
use crate::core::orchestrator::{Orchestrator, OrchestratorConfig};
use crate::utils::executor::ExecutorMode;

pub struct ScanningStageSwarm {
    pub swarm_mode: bool,
    pub ai_router: Option<Arc<crate::core::ai::TieredAIRouter>>,
    pub max_tokens: u32,
    pub proxy_manager: Option<Arc<crate::utils::proxy::ProxyManager>>,
}

pub struct ScanningStageDashboard {
    pub dashboard_tx: Option<tokio::sync::broadcast::Sender<crate::models::Finding>>,
    pub dashboard_targets: Option<Arc<dashmap::DashMap<String, TargetHost>>>,
}

pub fn spawn_scanning_stage<M: ExecutorMode>(
    scan_rx: mpsc::Receiver<TargetHost>,
    sink_tx: mpsc::Sender<TargetHost>,
    shutdown_token: tokio_util::sync::CancellationToken,
    config: OrchestratorConfig<M>,
    swarm: ScanningStageSwarm,
    dashboard: ScanningStageDashboard,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut orchestrator = Orchestrator::new(config);

        if let (Some(tx), Some(targets)) = (dashboard.dashboard_tx, dashboard.dashboard_targets) {
            orchestrator.with_dashboard_preconfigured(tx, targets);
        }

        if swarm.swarm_mode {
            if let Some(router) = swarm.ai_router {
                orchestrator = orchestrator.with_swarm_mode(true, swarm.max_tokens, router, swarm.proxy_manager);
            }
        }
        orchestrator.run(scan_rx, sink_tx, shutdown_token).await;
    })
}
