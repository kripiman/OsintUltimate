use crate::models::{Finding, TargetHost, Category, Severity};
use crate::core::pipeline::Pipeline;
use crate::core::ai::{TieredAIRouter, AdaptiveContext, RouteLevel};
use crate::core::approval_gate::ApprovalGate;
use anyhow::{Result, Context};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{info, warn, error, debug};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use super::budget::{TokenBudget, TokenGuard, TaskPriority};

use crate::utils::executor::{StealthExecutor, ExecutorMode};
use crate::core::persistence::PersistenceOrchestrator;
use crate::models::{EngagementState, Objective, ObjectivePhase};
use crate::models::constants::FINDING_ATTACK_PATH;
use crate::plugins::detection_evasion::jitter::EvasionJitter;
use crate::utils::config::Config;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentRole {
    Planner,
    Scout,
    Exploiter,
    C2Operator,
    GhostReporter,
}

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

pub struct AgentTask<'a, M: ExecutorMode> {
    pub finding: Finding,
    pub target: &'a TargetHost,
    pub attack_context: Option<String>,
    pub tx: &'a mut mpsc::Sender<Finding>,
    pub adaptive_ctx: &'a mut AdaptiveContext,
    pub sink_tx: &'a mpsc::Sender<TargetHost>,
    pub guard: TokenGuard,
    pub jitter: Arc<EvasionJitter>,
    pub _marker: std::marker::PhantomData<M>,
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
        let fired_chains = Arc::new(dashmap::DashSet::new()); // NEW-3: Persistent across findings
        let adaptive_context = AdaptiveContext::default();
        let correlation_engine_inner = crate::core::correlation::CorrelationEngine::load("swarm_ce_state.json")
            .unwrap_or_else(|_| crate::core::correlation::CorrelationEngine::new());
        let correlation_engine = Arc::new(tokio::sync::Mutex::new(correlation_engine_inner));
        let inventory = Arc::new(crate::core::swarm::inventory::SwarmInventory::new());
        
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
                crate::core::correlation::ingestor::Ingestor::ingest_finding(&mut ce, finding.clone());
                
                // Phase 6: Mark owned nodes based on credentials
                if finding.core.id == crate::models::constants::FINDING_NTLM_HASH_CAPTURED || 
                   finding.core.id == crate::models::constants::FINDING_CREDENTIALS_FOUND {
                    let sid = finding.evidence.evidence.as_ref()
                        .and_then(|e| e.data.get("SID"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    
                    let resolved_sid = if sid.is_none() {
                        finding.evidence.evidence.as_ref()
                            .and_then(|e| e.data.get("username").or_else(|| e.data.get("user")))
                            .and_then(|v| v.as_str())
                            .and_then(|u| ce.find_sid_by_username(u))
                    } else {
                        sid
                    };

                    if let Some(s) = resolved_sid {
                        ce.mark_node_as_owned(&s);
                    }
                }
                
                let paths = ce.get_critical_paths();
                let graph = ce.get_graph(); // Need a getter for ARCH-8 Finding construction

                paths.into_iter()
                    .filter(|path| !seen_finding_ids.contains(&format!("{}-{}", crate::models::constants::FINDING_ATTACK_PATH, path.pattern_signature())))
                    .map(|path| {
                        let signature = path.pattern_signature();
                        let next_hop_host = path.nodes.iter().skip(1)
                            .find_map(|node_id| {
                                let node = graph.nodes.get(node_id)?;
                                let props = node.evidence.evidence.as_ref()?.data.get("properties")?;
                                let is_computer = node.evidence.evidence.as_ref()?.data.get("type").and_then(|v| v.as_str()) == Some("Computer");
                                if is_computer {
                                    props.get("dNSHostName").or_else(|| props.get("name")).and_then(|v| v.as_str()).map(|s| s.to_string())
                                } else { None }
                            });

                        let mut f = Finding::new(
                            &format!("{}-{}", crate::models::constants::FINDING_ATTACK_PATH, signature),
                            crate::models::Category::Windows,
                            crate::models::Severity::High,
                            &format!("Critical Attack Path detected: {}", path.description),
                            serde_json::json!({
                                "nodes": path.nodes,
                                "description": path.description,
                                "total_cvss": path.total_cvss,
                                "signature": signature,
                                "host": next_hop_host
                            })
                        );
                        f.core.scope_id = initial_target.scope_id.clone();
                        f
                    })
                    .collect()
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
                if path_finding.evidence.evidence.as_ref()
                    .and_then(|e| e.data.get("nodes"))
                    .and_then(|n| n.as_array())
                    .map(|nodes| nodes.iter().any(|nid| nid.as_str() == Some(&finding.core.id)))
                    .unwrap_or(false) 
                {
                    is_on_critical_path = true;
                }
            }

            // --- PHASE 5.3: FAST-PATH INGESTION ---
            inventory.ingest_finding(finding.clone(), crate::core::swarm::inventory::TrustLevel::Private);

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
                let reactive_findings = crate::core::reactive_engine::evaluate(
                    &rules,
                    &[finding_spawn],
                    &initial_target_spawn,
                    pipeline_spawn.get_plugins_ref(),
                    pipeline_spawn.get_layer_policy(),
                    &approval_gate_spawn,
                    &fired_chains_spawn,
                    Some(&inventory_spawn),
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

            let mut ce_handle = correlation_engine.lock().await;
            let attack_context = ce_handle.get_context_summary(&finding.core.id);
            drop(ce_handle);
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
                            ce.add_finding(finding_clone);
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
        let ce = correlation_engine.lock().await;
        if let Err(e) = ce.save("swarm_ce_state.json") {
            warn!("⚠️ SWARM: Failed to persist Correlation Engine state: {}", e);
        } else {
            info!("💾 SWARM: Correlation Engine state persisted to swarm_ce_state.json");
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
                let verified = finding.evidence.evidence.as_ref().map(|e| e.verified).unwrap_or(false);
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
        // NEW-1: Apply jitter before execution to simulate human timing
        task.jitter.apply().await;
        info!("🔍 SWARM [Scout]: Profundizando en hallazgo de infraestructura: {}", task.finding.core.title);
        
        let metadata = self.pipeline.get_plugin_metadata();
        match self.router.decide_action(&task.finding, task.target, &metadata, task.attack_context.as_deref(), Some(task.adaptive_ctx)).await {
            Ok(Some((action, tactical))) => {
                task.guard.commit(200); 

                let mut task_target = task.target.clone();
                task_target.tactical_context = Arc::new(tactical);
                
                let results = self.pipeline.run_specific_plugin(&action, &task_target).await?;
                for nf in results {
                    let _ = task.tx.send(nf).await;
                }
            }
            Ok(None) => {
            }
            Err(e) => {
                return Err(e);
            }
        }
        
        let mut sink_target = task.target.clone();
        sink_target.findings = Arc::new(vec![task.finding]);
        let _ = task.sink_tx.send(sink_target).await;
        
        Ok(())
    }

    async fn execute_exploiter(
        &self,
        task: AgentTask<'_, M>,
    ) -> Result<()> {
        // NEW-1: Apply jitter before execution
        task.jitter.apply().await;
        let mut finding = task.finding;
        info!("💥 SWARM [Exploiter]: Intentando validación/explotación de: {} [Posture: STRIKE]", finding.core.title);
        
        task.adaptive_ctx.posture = crate::core::ai::Posture::Strike;
        
        match self.router.analyze(&finding, task.target, task.attack_context.as_deref()).await {
            Ok(analysis) => {
                let usage = analysis.usage.total_tokens;
                task.guard.commit(usage); 
                finding = finding.with_ai_analysis(analysis.clone());
                
                let poc_validator = crate::core::validation::PocValidator::new(
                    self.router.clone(),
                    self.approval_gate.clone(),
                    self.operator.clone(),
                    self.executor.clone(),
                    self.policy.clone(),
                    self.proxy_manager.clone(),
                );
                
                if analysis.risk_score >= 7 {
                    let _ = poc_validator.validate(&mut finding, task.target, task.attack_context.as_deref()).await;
                }
            }
            Err(e) => {
                warn!("⚠️ SWARM [Exploiter]: Error en análisis de explotación: {}", e);
            }
        }

        let mut sink_target = task.target.clone();
        sink_target.findings = Arc::new(vec![finding]);
        let _ = task.sink_tx.send(sink_target).await;

        Ok(())
    }

    async fn execute_c2_operator(
        &self,
        finding: Finding,
        target: &TargetHost,
        adaptive_ctx: &mut AdaptiveContext,
        sink_tx: &mpsc::Sender<TargetHost>,
        guard: TokenGuard,
        jitter: Arc<EvasionJitter>,
    ) -> Result<()> {
        // NEW-1: Jitter post-exploitation cadence
        jitter.apply().await;
        info!("🔱 SWARM [C2Operator]: Orchestrating offensive persistence for {} [Posture: BREACH]", target.host);
        
        adaptive_ctx.posture = crate::core::ai::Posture::Breach;
        guard.commit(500);

        let orchestrator = PersistenceOrchestrator::new(self.router.clone(), self.executor.clone());
        if let Ok(plan) = orchestrator.generate_plan(&finding).await {
            info!("🎯 SWARM [C2Operator]: Tactical plan generated. Consolidating access...");
            if let Err(e) = orchestrator.consolidate(&plan, target).await {
                warn!("⚠️ SWARM [C2Operator]: Consolidation failed: {}", e);
            } else {
                if let Ok(true) = orchestrator.verify_access(&plan, target).await {
                    info!("🛡️ SWARM [C2Operator]: Persistence Verified (APT-Level). Posture maintained.");
                } else {
                    warn!("⚠️ SWARM [C2Operator]: Persistence verification failed. Payload might have been detected or blocked.");
                }
            }
        }

        let operators = self.pipeline.get_c2_operators();
        if operators.is_empty() {
             warn!("⚠️ SWARM [C2Operator]: No se encontraron operadores C2 cargados en la pipeline.");
        }

        for c2 in operators {
            match c2.verify_session(target).await {
                Ok(state) => {
                    use crate::core::c2::SessionState;
                    if state == SessionState::Sovereign || state == SessionState::Established {
                        info!("🎯 SWARM [C2Operator]: Sesión activa detectada. Omitiendo despliegue.");
                        return Ok(());
                    }

                    if let Ok(payload_path) = c2.prepare_payload(target).await {
                        info!("🚀 SWARM [C2Operator]: Payload preparado en {}. Iniciando despliegue...", payload_path);
                        let _ = c2.deploy_payload(target, &payload_path).await;
                        
                        let mut sink_target = target.clone();
                        let mut final_findings = vec![finding.clone()];
                        final_findings.push(Finding::new(
                            "C2-PERSISTENCE-DEPLOYED",
                            Category::Vulnerability,
                            Severity::High,
                            &format!("Persistence payload deployed via C2 Operator: {}", payload_path),
                            serde_json::json!({ "path": payload_path, "target": target.host })
                        ));
                        sink_target.findings = Arc::new(final_findings);
                        let _ = sink_tx.send(sink_target).await;
                        return Ok(());
                    }
                }
                Err(e) => debug!("🐝 SWARM [C2Operator]: Operador falló verificación: {}", e),
            }
        }

        warn!("⚠️ SWARM [C2Operator]: No se pudo establecer persistencia con ningún operador disponible.");
        let mut sink_target = target.clone();
        sink_target.findings = Arc::new(vec![finding]);
        let _ = sink_tx.send(sink_target).await;
        Ok(())
    }

    async fn execute_reporter(
        &self,
        finding: Finding,
        target: &TargetHost,
        sink_tx: &mpsc::Sender<TargetHost>,
        guard: TokenGuard,
    ) -> Result<()> {
        debug!("📝 SWARM [Reporter]: Archivando hallazgo informativo: {}", finding.core.title);
        guard.commit(0);
        let mut sink_target = target.clone();
        sink_target.findings = Arc::new(vec![finding]);
        let _ = sink_tx.send(sink_target).await;
        Ok(())
    }
}
