use crate::models::{TargetHost, Finding};
use crate::plugins::ScannerPlugin;
use std::sync::Arc;
use crate::core::capability_layer::ScanLayerPolicy;
use crate::core::approval_gate::ApprovalGate;
use crate::utils::executor::{StealthExecutor, ExecutorMode};

pub struct Orchestrator<M: ExecutorMode> {
    pub plugins: Arc<Vec<Box<dyn ScannerPlugin>>>,
    pub concurrency: usize,
    pub layer_policy: ScanLayerPolicy,
    pub approval_gate: Arc<ApprovalGate>,
    pub blackarch_bridge: Arc<crate::core::blackarch::BlackArchBridge>,
    pub memory_semaphore: Arc<tokio::sync::Semaphore>,
    pub memory_monitor: Arc<crate::utils::memory_monitor::MemoryMonitor>,
    pub concurrency_semaphore: Arc<tokio::sync::Semaphore>,
    pub dashboard_tx: Option<tokio::sync::broadcast::Sender<Finding>>,
    pub dashboard_targets: Arc<dashmap::DashMap<String, TargetHost>>,
    pub swarm_mode: bool,
    pub max_tokens: u32,
    pub ai_router: Option<Arc<crate::core::ai::TieredAIRouter>>,
    pub sandbox: Arc<crate::core::sandbox::SandboxDispatcher>,
    pub proxy_manager: Option<Arc<crate::utils::proxy::ProxyManager>>,
    pub policy: Arc<dyn crate::core::policy::PolicyProvider>,
    pub executor: Arc<StealthExecutor<M>>,
    pub strict_scope: bool,
    pub db_pool: Option<sqlx::PgPool>,
    pub current_scan_id: Option<i64>,
    pub inventory: Arc<crate::core::orchestrator::swarm::inventory::SwarmInventory>,
    #[cfg(feature = "sovereign")]
    pub sliver_ca_path: Option<String>,
    #[cfg(feature = "sovereign")]
    pub sliver_cert_path: Option<String>,
    #[cfg(feature = "sovereign")]
    pub sliver_key_path: Option<String>,
    #[cfg(feature = "sovereign")]
    pub sliver_server_addr: Option<String>,
}

pub struct OrchestratorConfig<M: ExecutorMode> {
    pub plugins: Arc<Vec<Box<dyn ScannerPlugin>>>,
    pub concurrency: usize,
    pub layer_policy: ScanLayerPolicy,
    pub approval_gate: Arc<ApprovalGate>,
    pub blackarch_bridge: Arc<crate::core::blackarch::BlackArchBridge>,
    pub memory_monitor: Arc<crate::utils::memory_monitor::MemoryMonitor>,
    pub sandbox: Arc<crate::core::sandbox::SandboxDispatcher>,
    pub policy: Arc<dyn crate::core::policy::PolicyProvider>,
    pub executor: Arc<StealthExecutor<M>>,
    pub strict_scope: bool,
    pub feedback_tx: Option<tokio::sync::mpsc::Sender<TargetHost>>,
    pub db_pool: Option<sqlx::PgPool>,
    pub current_scan_id: Option<i64>,
    pub inventory: Option<Arc<crate::core::orchestrator::swarm::inventory::SwarmInventory>>,
    #[cfg(feature = "sovereign")]
    pub sliver_ca_path: Option<String>,
    #[cfg(feature = "sovereign")]
    pub sliver_cert_path: Option<String>,
    #[cfg(feature = "sovereign")]
    pub sliver_key_path: Option<String>,
    #[cfg(feature = "sovereign")]
    pub sliver_server_addr: Option<String>,
}
