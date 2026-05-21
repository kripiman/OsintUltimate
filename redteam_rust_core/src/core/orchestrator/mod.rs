use crate::models::{TargetHost, Finding, Severity, TargetStatus};
use std::sync::Arc;
use futures::stream::StreamExt;
use tracing::info;
#[cfg(feature = "sovereign")]
use tracing::error;
use crate::utils::executor::ExecutorMode;

pub mod monitor;
pub mod dispatch;
pub mod reactive;
pub mod enrichment;
pub mod scope_guard;
pub mod lifecycle;
pub mod swarm;
pub mod c2;

pub use lifecycle::{Orchestrator, OrchestratorConfig};

impl<M: ExecutorMode> Orchestrator<M> {
    pub fn new(config: OrchestratorConfig<M>) -> Self {
        let hard_limit = config.memory_monitor.hard_limit_mb();
        let memory_semaphore = Arc::new(tokio::sync::Semaphore::new(hard_limit as usize));
        let concurrency_semaphore = Arc::new(tokio::sync::Semaphore::new(config.concurrency));

        if let Some(feedback_tx) = &config.feedback_tx {
            for scanner in config.plugins.iter() {
                scanner.set_feedback_channel(feedback_tx.clone());
            }
        }

        Self {
            plugins: config.plugins,
            concurrency: config.concurrency,
            layer_policy: config.layer_policy,
            approval_gate: config.approval_gate,
            blackarch_bridge: config.blackarch_bridge,
            memory_semaphore,
            memory_monitor: config.memory_monitor,
            concurrency_semaphore,
            dashboard_tx: None,
            dashboard_targets: Arc::new(dashmap::DashMap::new()),
            swarm_mode: false,
            max_tokens: 0,
            ai_router: None,
            sandbox: config.sandbox,
            proxy_manager: None,
            policy: config.policy,
            executor: config.executor,
            strict_scope: config.strict_scope,
            db_pool: config.db_pool,
            current_scan_id: config.current_scan_id,
            inventory: config.inventory.unwrap_or_else(|| Arc::new(crate::core::orchestrator::swarm::inventory::SwarmInventory::new())),
            #[cfg(feature = "sovereign")]
            sliver_ca_path: config.sliver_ca_path,
            #[cfg(feature = "sovereign")]
            sliver_cert_path: config.sliver_cert_path,
            #[cfg(feature = "sovereign")]
            sliver_key_path: config.sliver_key_path,
            #[cfg(feature = "sovereign")]
            sliver_server_addr: config.sliver_server_addr,
        }
    }

    pub fn with_swarm_mode(mut self, enabled: bool, max_tokens: u32, router: Arc<crate::core::ai::TieredAIRouter>, proxy_manager: Option<Arc<crate::utils::proxy::ProxyManager>>) -> Self {
        self.swarm_mode = enabled;
        self.max_tokens = max_tokens;
        self.ai_router = Some(router);
        self.proxy_manager = proxy_manager;
        self
    }

    pub fn with_dashboard_preconfigured(&mut self, tx: tokio::sync::broadcast::Sender<Finding>, current_targets: Arc<dashmap::DashMap<String, TargetHost>>) {
        self.dashboard_tx = Some(tx);
        self.dashboard_targets = current_targets;
    }

    pub async fn run(
        self,
        input_rx: tokio::sync::mpsc::Receiver<TargetHost>,
        output_tx: tokio::sync::mpsc::Sender<TargetHost>,
        shutdown_token: tokio_util::sync::CancellationToken, 
    ) {
        info!("Orchestrator started. Concurrency: {}", self.concurrency);
        
        // Lifecycle Monitor
        tokio::spawn(monitor::run_monitor_loop(
            self.plugins.clone(),
            self.dashboard_tx.clone(),
            shutdown_token.clone()
        ));

        // Sliver C2 Feedback
        #[cfg(feature = "sovereign")]
        if let Some(addr) = &self.sliver_server_addr {
            let ca = self.sliver_ca_path.as_ref().and_then(|p| std::fs::read(p).ok());
            let cert = self.sliver_cert_path.as_ref().and_then(|p| std::fs::read(p).ok());
            let key = self.sliver_key_path.as_ref().and_then(|p| std::fs::read(p).ok());
            
            let feedback_loop = crate::core::orchestrator::c2::sliver_feedback::SliverFeedbackLoop::new(
                addr.clone(),
                self.inventory.clone(),
                ca, cert, key
            );
            
            tokio::spawn(async move {
                if let Err(e) = feedback_loop.run().await {
                    error!("🚨 V15.5 C2_FEEDBACK: Sliver feedback loop error: {}", e);
                }
            });
        }
        
        let stream = futures::stream::unfold((input_rx, shutdown_token.clone(), output_tx.clone()), |(mut rx, token, out_tx)| async move {
            tokio::select! {
                val = rx.recv() => val.map(|t| (t, (rx, token, out_tx))),
                _ = token.cancelled() => {
                    rx.close();
                    while let Some(mut remaining_target) = rx.recv().await {
                        remaining_target.status = TargetStatus::Dead;
                        remaining_target.version += 1;
                        let mut findings = (*remaining_target.findings).clone();
                        findings.push(Finding::new(
                            "SHUTDOWN_ABORT",
                            crate::models::Category::Availability,
                            Severity::Info,
                            "Target scan aborted due to graceful shutdown",
                            serde_json::json!({"host": remaining_target.host})
                        ));
                        remaining_target.findings = Arc::new(findings);
                        let _ = tokio::time::timeout(std::time::Duration::from_millis(100), out_tx.send(remaining_target)).await;
                    }
                    None
                }
            }
        });

        tokio::pin!(stream);

        let swarm_mode = self.swarm_mode;
        let ai_router = self.ai_router.clone();

        match (swarm_mode, ai_router, Some(output_tx.clone())) {
            (true, Some(router), Some(out_tx)) => {
                info!("🐝 ORCHESTRATOR: Entering Swarm Mode (Max Tokens: {})", self.max_tokens);
                let pipeline = Arc::new(crate::core::pipeline::Pipeline::new_minimal(self.plugins.clone(), self.sandbox.clone(), None, None));
                let swarm = crate::core::orchestrator::swarm::SwarmOrchestrator::new(crate::core::orchestrator::swarm::SwarmConfig {
                    router,
                    pipeline,
                    approval_gate: self.approval_gate.clone(),
                    max_tokens: self.max_tokens,
                    proxy_manager: self.proxy_manager.clone(),
                    executor: self.executor.clone(),
                    policy: self.policy.clone(),
                });

                let swarm_stream = stream.map(move |target| {
                    let swarm = swarm.clone();
                    let out_tx = out_tx.clone();
                    async move {
                        let _ = swarm.run(target.clone(), out_tx).await;
                        target
                    }
                }).buffer_unordered(self.concurrency);

                tokio::pin!(swarm_stream);
                while swarm_stream.next().await.is_some() {}
            }
            _ => {
                let mut processed_stream = stream.map(|target| {
                    let plugins = self.plugins.clone();
                    let lp = self.layer_policy;
                    let policy = self.policy.clone();
                    let strict_scope = self.strict_scope;
                    let approval_gate = self.approval_gate.clone();
                    let blackarch_bridge = self.blackarch_bridge.clone();
                    let memory_semaphore = self.memory_semaphore.clone();
                    let memory_monitor = self.memory_monitor.clone();
                    let dashboard_tx = self.dashboard_tx.clone();
                    let dashboard_targets = self.dashboard_targets.clone();
                    let inventory = self.inventory.clone();
                    let concurrency_semaphore = self.concurrency_semaphore.clone();
                    
                    let ctx = dispatch::TargetProcessContext {
                        plugins,
                        lp,
                        policy,
                        strict_scope,
                        approval_gate,
                        blackarch_bridge,
                        memory_semaphore,
                        memory_monitor,
                        dashboard_tx,
                        dashboard_targets,
                        inventory,
                        approval_timeout_secs: None,
                        concurrency_semaphore,
                    };
                    
                    async move {
                        dispatch::process_target(target, ctx).await
                    }
                }).buffer_unordered(self.concurrency);

                while let Some(mut result) = processed_stream.next().await {
                    result.scan_id = self.current_scan_id;
                    if let Some(ref pool) = self.db_pool {
                        let _ = crate::core::temporal::diff_target(pool, &mut result).await;
                    }
                    let _ = output_tx.send(result).await;
                }
            }
        }
        info!("Orchestrator finished processing.");
    }
}
