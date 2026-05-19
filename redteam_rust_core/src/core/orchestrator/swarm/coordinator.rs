use crate::models::{Finding, TargetHost, Category, Severity};
use crate::core::pipeline::Pipeline;
use crate::core::ai::{TieredAIRouter, AdaptiveContext, RouteLevel};
use crate::core::approval_gate::ApprovalGate;
use anyhow::{Result, Context};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{info, warn, error, debug};
use std::collections::HashSet;

use super::budget::{TokenBudget, TokenGuard, TaskPriority};

use crate::utils::executor::{StealthExecutor, ExecutorMode};
use crate::models::{EngagementState, Objective, ObjectivePhase};
use crate::models::constants::FINDING_ATTACK_PATH;
use crate::plugins::detection_evasion::jitter::EvasionJitter;
use crate::utils::config::Config;

use super::agent::{AgentRole, AgentTask};
use super::correlation::ce_state_path;

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

pub struct SwarmConfig<M: ExecutorMode> {
    pub router: Arc<TieredAIRouter>,
    pub pipeline: Arc<Pipeline<M>>,
    pub approval_gate: Arc<ApprovalGate>,
    pub max_tokens: u32,
    pub proxy_manager: Option<Arc<crate::utils::proxy::ProxyManager>>,
    pub executor: Arc<StealthExecutor<M>>,
    pub policy: Arc<dyn crate::core::policy::PolicyProvider>,
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

    pub fn clone_for_spawn(&self) -> Self {
        self.clone()
    }


    pub async fn run(&self, initial_target: TargetHost, sink_tx: mpsc::Sender<TargetHost>) -> Result<()> {
        info!("🐝 SWARM: Iniciando enjambre multi-agente para {}", initial_target.host);
        
        {
            let mut state_lock = self.engagement.lock().await;
            if state_lock.is_none() {
                let mut state = EngagementState::new("ENG-001", "Default Mission");
                let root_obj = Objective::new("OBJ-ROOT", "Initial Exploration", &format!("Explore target {}", initial_target.host), ObjectivePhase::Recon);
                state.opplan.add_objective(root_obj)?;
                *state_lock = Some(state);
                info!("🗺️ SWARM [V15]: OPPLAN Framework initialized.");
            }
        }
        
        if let Some(ref pm) = self.proxy_manager {
            info!("⏳ SWARM: Verificando integridad de egreso (ProxyManager readiness)...");
            pm.wait_for_readiness(std::time::Duration::from_secs(30))
                .await
                .context("V14.1 OPSEC Block: Swarm cannot start without healthy egress proxies.")?;
            info!("✅ SWARM: Egress verificado. Sparking the swarm.");
        }
        
        let mut seen_finding_ids = HashSet::new();
        let adaptive_context = AdaptiveContext::default();
        
        // BUG-NEW-03 FIX: Use absolute, OS-specific path for state
        let state_path = ce_state_path();
        
        let correlation_engine_inner = crate::core::correlation::CorrelationEngine::load(&state_path)
            .unwrap_or_else(|_| crate::core::correlation::CorrelationEngine::new());
            
        // BUG-W31-05 FIX: Restore fired_chains from persistent state
        let fired_chains = Arc::new(dashmap::DashSet::new());
        for chain in &correlation_engine_inner.fired_chains {
            fired_chains.insert(chain.clone());
        }
        
        let correlation_engine = Arc::new(tokio::sync::Mutex::new(correlation_engine_inner));
        let inventory = Arc::new(crate::core::orchestrator::swarm::inventory::SwarmInventory::new());
        
        let (discovery_tx, mut discovery_rx) = mpsc::channel(100);
        let pipeline = self.pipeline.clone();
        let target = initial_target.clone();
        
        let config = Config::from_env();
        let jitter = Arc::new(EvasionJitter::new(config.post_exploit_min_delay_ms, config.post_exploit_max_delay_ms));
        
        let pipeline_clone = pipeline.clone();
        let discovery_tx_clone = discovery_tx.clone();
        let _handle = tokio::spawn(async move {
            let _ = pipeline_clone.run_discovery(&target, discovery_tx_clone).await;
        });

        let mut join_set = tokio::task::JoinSet::new();
        let agent_semaphore = Arc::new(tokio::sync::Semaphore::new(10));
        let max_pending_tasks = 50; 

        if !self.policy.is_target_allowed(&initial_target.host) {
            error!("🛡️ V14.2 SCOPE VIOLATION: Target {} is NOT authorized in policy.json. Aborting swarm.", initial_target.host);
            return Ok(());
        }

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

            if seen_finding_ids.contains(&finding.core.id) { continue; }
            seen_finding_ids.insert(finding.core.id.clone());
            
            // BUG-3: Collect all work inside lock, drop lock BEFORE sending to channel.
            let critical_paths_to_emit: Vec<crate::models::Finding> = {
                let mut ce = correlation_engine.lock().await;
                super::correlation::process_correlation(&mut ce, &finding, &initial_target.scope_id, &seen_finding_ids)
            };

            // Send outside lock
            let mut is_on_critical_path = false;
            for path_finding in &critical_paths_to_emit {
                // NEW-1: Do NOT jitter in main loop. Move to emission task or ignore for internal findings.
                // However, we want the DISCOVERY to be jittered when the agent actually executes.
                // For internal "ATTACK-PATH-DISCOVERED" findings, we send them immediately to be processed.
                info!("🔱 V14.1 SOVEREIGN: Critical Attack Path discovered! Injecting finding into swarm.");
                let _ = discovery_tx.send(path_finding.clone()).await;
                
                // BUG-12 Optimization: Check if current finding is part of a critical path we just found
                if path_finding.evidence.primary.as_ref()
                    .and_then(|e| e.data.get("nodes"))
                    .and_then(|n| n.as_array())
                    .map(|nodes| nodes.iter().any(|nid| nid.as_str() == Some(&finding.core.id)))
                    .unwrap_or(false) 
                {
                    is_on_critical_path = true;
                }
            }

            // --- PHASE 5.3: FAST-PATH INGESTION ---
            inventory.ingest_finding(finding.clone(), crate::core::orchestrator::swarm::inventory::TrustLevel::Private);

            // NEW-2: Async Reactive Engine integration. Do NOT block main loop with plugin scans.
            let rules = crate::core::reactive_engine::get_all_rules();
            let fired_chains_spawn = fired_chains.clone();
            let discovery_tx_spawn = discovery_tx.clone();
            let inventory_spawn = inventory.clone();
            let pipeline_spawn = self.pipeline.clone();
            let initial_target_spawn = initial_target.clone();
            let finding_spawn = finding.clone();
            let approval_gate_spawn = self.approval_gate.clone();

            tokio::spawn(async move {
                let ctx = crate::core::reactive_engine::ReactiveContext {
                    findings: &[finding_spawn],
                    target: &initial_target_spawn,
                    plugins: pipeline_spawn.get_plugins_ref(),
                    layer_policy: pipeline_spawn.get_layer_policy(),
                    approval_gate: &approval_gate_spawn,
                    fired_chains: &fired_chains_spawn,
                    inventory: Some(&inventory_spawn),
                };
                let reactive_findings = crate::core::reactive_engine::evaluate(
                    &rules,
                    ctx,
                ).await;

                for rf in reactive_findings {
                    let _ = discovery_tx_spawn.send(rf).await;
                }
            });

            let mut role = self.plan_next_step(&finding, &initial_target).await?;
            
            // BUG-12 Optimization: Reuse critical path calculation result
            if is_on_critical_path && finding.core.category == Category::Vulnerability {
                info!("🔱 V14.1 SOVEREIGN: High-value AD path detected! Prioritizing pivot for {}.", finding.core.id);
                role = AgentRole::Exploiter;
            }

            // BUG-W31-08 FIX: Capture context summary while holding lock to prevent TOCTOU
            let attack_context = {
                let mut ce_handle = correlation_engine.lock().await;
                ce_handle.get_context_summary(&finding.core.id)
            };
            debug!("🐝 SWARM [Planner]: Asignando hallazgo {} al agente {:?}", finding.core.id, role);

            let orchestrator = Arc::new(self.clone_for_spawn()); 
            let finding_clone = finding.clone();
            let target_clone = initial_target.clone();
            let mut scout_tx = discovery_tx.clone();
            let mut ctx_clone = adaptive_context.clone();
            let ce_clone = correlation_engine.clone();
            let sink_tx_clone = sink_tx.clone();
            let semaphore = agent_semaphore.clone();
            let jitter_task = jitter.clone();

            let priority = match role {
                AgentRole::Planner => TaskPriority::High,
                AgentRole::Exploiter => TaskPriority::Normal,
                _ => TaskPriority::Low,
            };

            let guard = match TokenGuard::new(self.budget.clone(), 1000, priority) {
                Some(g) => g,
                None => {
                    warn!("💸 SWARM: No hay presupuesto suficiente para spawnear agente {:?} (Hallazgo {}). Skipping.", role, finding.core.id);
                    continue;
                }
            };

            join_set.spawn(async move {
                let _permit = semaphore.acquire().await.ok();
                
                use std::panic::AssertUnwindSafe;
                use futures::FutureExt;

                let finding_id = finding_clone.core.id.clone();
                let result = AssertUnwindSafe(async {
                    if orchestrator.budget.current_effective_total() > (orchestrator.budget.max_tokens as f64 * 0.95) as u32 
                       && role != AgentRole::GhostReporter {
                        warn!("🛡️ SWARM: CRITICAL BUDGET LIMIT! Tokens > 95%. Forcing emergency pivot to Passive Reporter for {}.", finding_id);
                        return orchestrator.execute_reporter(finding_clone, &target_clone, &sink_tx_clone, guard).await;
                    }

                    match role {
                        AgentRole::Scout => orchestrator.execute_scout(AgentTask::<M> {
                            finding: finding_clone,
                            target: &target_clone,
                            attack_context,
                            tx: &mut scout_tx,
                            adaptive_ctx: &mut ctx_clone,
                            sink_tx: &sink_tx_clone,
                            guard,
                            jitter: jitter_task.clone(),
                            _marker: std::marker::PhantomData,
                        }).await,
                        AgentRole::Exploiter => orchestrator.execute_exploiter(AgentTask::<M> {
                            finding: finding_clone,
                            target: &target_clone,
                            attack_context,
                            tx: &mut scout_tx,
                            adaptive_ctx: &mut ctx_clone,
                            sink_tx: &sink_tx_clone,
                            guard,
                            jitter: jitter_task.clone(),
                            _marker: std::marker::PhantomData,
                        }).await,
                        AgentRole::C2Operator => orchestrator.execute_c2_operator(
                            finding_clone, 
                            &target_clone, 
                            &mut ctx_clone, 
                            &sink_tx_clone, 
                            guard,
                            jitter_task.clone()
                        ).await,
                        AgentRole::GhostReporter => orchestrator.execute_reporter(finding_clone, &target_clone, &sink_tx_clone, guard).await,
                        AgentRole::Planner => {
                            let mut ce = ce_clone.lock().await;
                            // BUG-W31-01 FIX: Use Ingestor instead of deleted method
                            crate::core::correlation::ingestor::Ingestor::ingest_finding(&mut ce, finding_clone);
                            guard.commit(0);
                            Ok(())
                        },
                    }
                }).catch_unwind().await;

                match result {
                    Ok(res) => res,
                    Err(_) => {
                        error!("🛑 SWARM CRITICAL: Agent {:?} for finding {} caught a PANIC. Isolating.", role, finding_id);
                        anyhow::bail!("Agent panicked")
                    }
                }
            });
        }
        
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
        
        // ARCH-9: Persist Correlation Engine state
        let mut ce = correlation_engine.lock().await;
        
        // BUG-W31-05 FIX: Sync fired_chains back to CE before persistence
        ce.fired_chains.clear();
        for chain in fired_chains.iter() {
            ce.fired_chains.insert(chain.key().clone());
        }

        let state_path = ce_state_path();
        if let Err(e) = ce.save(&state_path) {
            warn!("⚠️ SWARM: Failed to persist Correlation Engine state: {}", e);
        } else {
            info!("💾 SWARM: Correlation Engine state persisted to {:?} (HMAC verified)", state_path);
        }

        Ok(())
    }

    async fn plan_next_step(&self, finding: &Finding, target: &TargetHost) -> Result<AgentRole> {
        let _compressed = crate::core::ai::ContextCompressor::compress_swarm_context(finding, target);
        
        let level = if finding.core.severity == Severity::Critical { RouteLevel::Premium } else { RouteLevel::Mid };
        info!("🐝 SWARM [Planner]: Routing {} to {:?} tier.", finding.core.id, level);
        
        match finding.core.category {
            Category::Recon | Category::NetworkPort | Category::TechnologyStack => Ok(AgentRole::Scout),
            Category::Windows if finding.core.id.starts_with(FINDING_ATTACK_PATH) => Ok(AgentRole::Scout),
            Category::Vulnerability | Category::Misconfiguration | Category::CredentialLeak => {
                let verified = finding.evidence.primary.as_ref().map(|e| e.verified).unwrap_or(false);
                if verified && finding.core.severity >= Severity::High {
                    Ok(AgentRole::C2Operator)
                } else {
                    Ok(AgentRole::Exploiter)
                }
            },
            _ => Ok(AgentRole::GhostReporter),
        }
    }

    async fn execute_scout(
        &self,
        task: AgentTask<'_, M>,
    ) -> Result<()> {
        super::agent::execute_scout(self, task).await
    }

    async fn execute_exploiter(
        &self,
        task: AgentTask<'_, M>,
    ) -> Result<()> {
        super::agent::execute_exploiter(self, task).await
    }

    async fn execute_c2_operator(
        &self,
        finding: Finding,
        target: &TargetHost,
        adaptive_ctx: &mut crate::core::ai::AdaptiveContext,
        sink_tx: &mpsc::Sender<TargetHost>,
        guard: TokenGuard,
        jitter: Arc<EvasionJitter>,
    ) -> Result<()> {
        super::agent::execute_c2_operator(self, finding, target, adaptive_ctx, sink_tx, guard, jitter).await
    }

    async fn execute_reporter(
        &self,
        finding: Finding,
        target: &TargetHost,
        sink_tx: &mpsc::Sender<TargetHost>,
        guard: TokenGuard,
    ) -> Result<()> {
        super::agent::execute_reporter(finding, target, sink_tx, guard).await
    }
}
