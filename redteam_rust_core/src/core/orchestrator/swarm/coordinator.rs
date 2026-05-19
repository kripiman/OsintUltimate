use crate::models::{Finding, TargetHost};
use crate::core::pipeline::Pipeline;
use crate::core::ai::{TieredAIRouter, AdaptiveContext};
use crate::core::approval_gate::ApprovalGate;
use anyhow::{Result, Context};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{info, warn, error};
use std::collections::HashSet;
use super::budget::TokenBudget;
use crate::utils::executor::{StealthExecutor, ExecutorMode};
use crate::models::{EngagementState, Objective, ObjectivePhase};
use crate::plugins::detection_evasion::jitter::EvasionJitter;
use crate::utils::config::Config;
use super::correlation::ce_state_path;
use super::SwarmConfig;

#[derive(Clone)]
pub struct SwarmOrchestrator<M: ExecutorMode = crate::utils::executor::GhostMode> where M: Clone {
    pub router: Arc<TieredAIRouter>,
    pub pipeline: Arc<Pipeline<M>>,
    pub approval_gate: Arc<ApprovalGate>,
    pub budget: Arc<TokenBudget>,
    pub operator: crate::core::approval_gate::User,
    pub proxy_manager: Option<Arc<crate::utils::proxy::ProxyManager>>,
    pub executor: Arc<StealthExecutor<M>>,
    pub policy: Arc<dyn crate::core::policy::PolicyProvider>,
    pub engagement: Arc<tokio::sync::Mutex<Option<EngagementState>>>,
}

impl<M: ExecutorMode> SwarmOrchestrator<M> {
    pub fn new(config: SwarmConfig<M>) -> Self {
        let operator = crate::core::approval_gate::User {
            id: "swarm-orchestrator".to_string(),
            name: "Osint-Swarm".to_string(),
            role: crate::core::approval_gate::UserRole::RedTeamFull,
            authorized_at: chrono::Utc::now(),
        };
        Self {
            router: config.router,
            pipeline: config.pipeline,
            approval_gate: config.approval_gate,
            budget: Arc::new(TokenBudget::new(config.max_tokens)),
            operator,
            proxy_manager: config.proxy_manager,
            executor: config.executor,
            policy: config.policy,
            engagement: Arc::new(tokio::sync::Mutex::new(None)),
        }
    }

    pub fn clone_for_spawn(&self) -> Self { self.clone() }

    pub async fn run(&self, initial_target: TargetHost, sink_tx: mpsc::Sender<TargetHost>) -> Result<()> {
        info!("🐝 SWARM: Iniciando enjambre multi-agente para {}", initial_target.host);
        self.initialize_engagement(&initial_target).await?;
        if !self.verify_egress(&initial_target).await? { return Ok(()); }
        let state_path = ce_state_path();
        let (ce_inner, fired_chains) = self.setup_correlation_engine(&state_path);
        let correlation_engine = Arc::new(tokio::sync::Mutex::new(ce_inner));
        let inventory = Arc::new(crate::core::orchestrator::swarm::inventory::SwarmInventory::new());
        let (discovery_tx, mut discovery_rx) = mpsc::channel(100);
        self.spawn_discovery(initial_target.clone(), discovery_tx.clone());
        let mut seen_finding_ids = HashSet::new();
        let adaptive_context = AdaptiveContext::default();
        let config = Config::from_env();
        let jitter = Arc::new(EvasionJitter::new(config.post_exploit_min_delay_ms, config.post_exploit_max_delay_ms));
        let mut join_set = tokio::task::JoinSet::new();
        let agent_semaphore = Arc::new(tokio::sync::Semaphore::new(10));
        let max_pending_tasks = 50;

        while let Some(finding) = discovery_rx.recv().await {
            while join_set.len() >= max_pending_tasks {
                if let Some(res) = join_set.join_next().await {
                     match res {
                        Ok(Ok(_)) => {},
                        Ok(Err(e)) => error!("🐝 SWARM [Agent Error]: {}", e),
                        Err(e) => error!("🐝 SWARM [Task Error]: Join error: {}", e),
                    }
                } else {
                    break;
                }
            }
            if self.budget.is_exhausted() {
                warn!("💸 SWARM: Presupuesto de tokens agotado ({}). Deteniendo enjambre.", self.budget.current_total());
                break;
            }
            self.process_finding(
                finding,
                &mut seen_finding_ids,
                &correlation_engine,
                &fired_chains,
                &inventory,
                &discovery_tx,
                &mut join_set,
                &agent_semaphore,
                &jitter,
                &adaptive_context,
                &initial_target,
                &sink_tx,
            ).await?;
        }
        self.finalize_and_persist(&mut join_set, &correlation_engine, &fired_chains).await?;
        Ok(())
    }

    async fn initialize_engagement(&self, initial_target: &TargetHost) -> Result<()> {
        let mut state_lock = self.engagement.lock().await;
        if state_lock.is_none() {
            let mut state = EngagementState::new("ENG-001", "Default Mission");
            let root_obj = Objective::new("OBJ-ROOT", "Initial Exploration", &format!("Explore target {}", initial_target.host), ObjectivePhase::Recon);
            state.opplan.add_objective(root_obj)?;
            *state_lock = Some(state);
            info!("🗺️ SWARM [V15]: OPPLAN Framework initialized.");
        }
        Ok(())
    }

    async fn verify_egress(&self, initial_target: &TargetHost) -> Result<bool> {
        if let Some(ref pm) = self.proxy_manager {
            info!("⏳ SWARM: Verificando integridad de egreso (ProxyManager readiness)...");
            pm.wait_for_readiness(std::time::Duration::from_secs(30))
                .await
                .context("V14.1 OPSEC Block: Swarm cannot start without healthy egress proxies.")?;
            info!("✅ SWARM: Egress verificado. Sparking the swarm.");
        }
        if !self.policy.is_target_allowed(&initial_target.host) {
            error!("🛡️ V14.2 SCOPE VIOLATION: Target {} is NOT authorized in policy.json. Aborting swarm.", initial_target.host);
            return Ok(false);
        }
        Ok(true)
    }

    fn setup_correlation_engine(&self, state_path: &std::path::Path) -> (crate::core::correlation::CorrelationEngine, Arc<dashmap::DashSet<String>>) {
        let ce = crate::core::correlation::CorrelationEngine::load(state_path).unwrap_or_else(|_| crate::core::correlation::CorrelationEngine::new());
        let fired_chains = Arc::new(dashmap::DashSet::new());
        for chain in &ce.fired_chains { fired_chains.insert(chain.clone()); }
        (ce, fired_chains)
    }

    fn spawn_discovery(&self, target: TargetHost, tx: mpsc::Sender<Finding>) {
        let pipeline = self.pipeline.clone();
        tokio::spawn(async move {
            let _ = pipeline.run_discovery(&target, tx).await;
        });
    }

    async fn finalize_and_persist(
        &self,
        join_set: &mut tokio::task::JoinSet<Result<()>>,
        correlation_engine: &Arc<tokio::sync::Mutex<crate::core::correlation::CorrelationEngine>>,
        fired_chains: &Arc<dashmap::DashSet<String>>,
    ) -> Result<()> {
        while let Some(res) = join_set.join_next().await {
            match res {
                Ok(Ok(_)) => {},
                Ok(Err(e)) => error!("🐝 SWARM [Agent Error]: {}", e),
                Err(e) => {
                    if e.is_panic() {
                        error!("🛑 SWARM CRITICAL: Agent task PANICKED! Isolation active. Continuing other agents.");
                    } else {
                        error!("🐝 SWARM [Task Error]: Join error: {}", e);
                    }
                }
            }
        }
        info!("🛑 SWARM: Enjambre finalizado. Consumo total: {} tokens.", self.budget.current_total());
        let mut ce = correlation_engine.lock().await;
        ce.fired_chains.clear();
        for chain in fired_chains.iter() { ce.fired_chains.insert(chain.key().clone()); }
        let state_path = ce_state_path();
        if let Err(e) = ce.save(&state_path) {
            warn!("⚠️ SWARM: Failed to persist Correlation Engine state: {}", e);
        } else {
            info!("💾 SWARM: Correlation Engine state persisted to {:?} (HMAC verified)", state_path);
        }
        Ok(())
    }
}
