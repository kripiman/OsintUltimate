use crate::models::{Finding, TargetHost, Category, Severity};
use crate::core::orchestrator::swarm::budget::{TokenGuard, TaskPriority};
use crate::plugins::detection_evasion::jitter::EvasionJitter;
use crate::utils::executor::ExecutorMode;
use std::sync::Arc;
use tokio::sync::mpsc;
use std::collections::HashSet;
use crate::models::constants::FINDING_ATTACK_PATH;
use crate::core::ai::{RouteLevel, AdaptiveContext};

use crate::core::orchestrator::swarm::coordinator::SwarmOrchestrator;
use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentRole {
    Planner,
    Scout,
    Exploiter,
    C2Operator,
    GhostReporter,
}

pub struct AgentTask<'a, M: ExecutorMode> {
    pub finding: Finding,
    pub target: &'a TargetHost,
    pub attack_context: Option<String>,
    pub tx: &'a mut mpsc::Sender<Finding>,
    pub adaptive_ctx: &'a mut crate::core::ai::AdaptiveContext,
    pub sink_tx: &'a mpsc::Sender<TargetHost>,
    pub guard: TokenGuard,
    pub jitter: Arc<EvasionJitter>,
    pub _marker: std::marker::PhantomData<M>,
}

pub async fn execute_scout<M: ExecutorMode>(
    orchestrator: &SwarmOrchestrator<M>,
    task: AgentTask<'_, M>,
) -> Result<()> {
    task.jitter.apply().await;
    tracing::info!("🔍 SWARM [Scout]: Profundizando en hallazgo de infraestructura: {}", task.finding.core.title);
    
    let metadata = orchestrator.pipeline.get_plugin_metadata();
    match orchestrator.router.decide_action(&task.finding, task.target, &metadata, task.attack_context.as_deref(), Some(task.adaptive_ctx)).await {
        Ok(Some((action, tactical))) => {
            task.guard.commit(200); 

            let mut task_target = task.target.clone();
            task_target.tactical_context = Arc::new(tactical);
            
            let results = orchestrator.pipeline.run_specific_plugin(&action, &task_target).await?;
            for nf in results {
                let _ = task.tx.send(nf).await;
            }
        }
        Ok(None) => {}
        Err(e) => return Err(e),
    }
    
    let mut sink_target = task.target.clone();
    sink_target.findings = Arc::new(vec![task.finding]);
    let _ = task.sink_tx.send(sink_target).await;
    
    Ok(())
}

pub async fn execute_exploiter<M: ExecutorMode>(
    orchestrator: &SwarmOrchestrator<M>,
    task: AgentTask<'_, M>,
) -> Result<()> {
    task.jitter.apply().await;
    let mut finding = task.finding;
    tracing::info!("💥 SWARM [Exploiter]: Intentando validación/explotación de: {} [Posture: STRIKE]", finding.core.title);
    
    task.adaptive_ctx.posture = crate::core::ai::Posture::Strike;
    
    match orchestrator.router.analyze(&finding, task.target, task.attack_context.as_deref()).await {
        Ok(analysis) => {
            let usage = analysis.usage.total_tokens;
            task.guard.commit(usage); 
            finding = finding.with_ai_analysis(analysis.clone());
            
            let poc_validator = crate::core::validation::PocValidator::new(
                orchestrator.router.clone(),
                orchestrator.approval_gate.clone(),
                orchestrator.operator.clone(),
                orchestrator.executor.clone(),
                orchestrator.policy.clone(),
                orchestrator.proxy_manager.clone(),
            );
            
            if analysis.risk_score >= 7 {
                let _ = poc_validator.validate(&mut finding, task.target, task.attack_context.as_deref()).await;
            }
        }
        Err(e) => {
            tracing::warn!("⚠️ SWARM [Exploiter]: Error en análisis de explotación: {}", e);
        }
    }

    let mut sink_target = task.target.clone();
    sink_target.findings = Arc::new(vec![finding]);
    let _ = task.sink_tx.send(sink_target).await;

    Ok(())
}

pub async fn execute_c2_operator<M: ExecutorMode>(
    orchestrator: &SwarmOrchestrator<M>,
    finding: Finding,
    target: &TargetHost,
    adaptive_ctx: &mut crate::core::ai::AdaptiveContext,
    sink_tx: &mpsc::Sender<TargetHost>,
    guard: TokenGuard,
    jitter: Arc<EvasionJitter>,
) -> Result<()> {
    jitter.apply().await;
    tracing::info!("🔱 SWARM [C2Operator]: Orchestrating offensive persistence for {} [Posture: BREACH]", target.host);
    
    adaptive_ctx.posture = crate::core::ai::Posture::Breach;
    guard.commit(500);

    let persistence = crate::core::persistence::PersistenceOrchestrator::new(orchestrator.router.clone(), orchestrator.executor.clone());
    if let Ok(plan) = persistence.generate_plan(&finding).await {
        tracing::info!("🎯 SWARM [C2Operator]: Tactical plan generated. Consolidating access...");
        if let Err(e) = persistence.consolidate(&plan, target).await {
            tracing::warn!("⚠️ SWARM [C2Operator]: Consolidation failed: {}", e);
        } else {
            if let Ok(true) = persistence.verify_access(&plan, target).await {
                tracing::info!("🛡️ SWARM [C2Operator]: Persistence Verified (APT-Level). Posture maintained.");
            } else {
                tracing::warn!("⚠️ SWARM [C2Operator]: Persistence verification failed. Payload might have been detected or blocked.");
            }
        }
    }

    let operators = orchestrator.pipeline.get_c2_operators();
    if operators.is_empty() {
         tracing::warn!("⚠️ SWARM [C2Operator]: No se encontraron operadores C2 cargados en la pipeline.");
    }

    for c2 in operators {
        match c2.verify_session(target).await {
            Ok(state) => {
                use crate::core::orchestrator::c2::SessionState;
                if state == SessionState::Sovereign || state == SessionState::Established {
                    tracing::info!("🎯 SWARM [C2Operator]: Sesión activa detectada. Omitiendo despliegue.");
                    return Ok(());
                }

                if let Ok(payload_path) = c2.prepare_payload(target).await {
                    tracing::info!("🚀 SWARM [C2Operator]: Payload preparado en {}. Iniciando despliegue...", payload_path);
                    let _ = c2.deploy_payload(target, &payload_path).await;
                    
                    let mut sink_target = target.clone();
                    let mut final_findings = vec![finding.clone()];
                    final_findings.push(Finding::new(
                        "C2-PERSISTENCE-DEPLOYED",
                        crate::models::Category::Vulnerability,
                        crate::models::Severity::High,
                        &format!("Persistence payload deployed via C2 Operator: {}", payload_path),
                        serde_json::json!({ "path": payload_path, "target": target.host })
                    ));
                    sink_target.findings = Arc::new(final_findings);
                    let _ = sink_tx.send(sink_target).await;
                    return Ok(());
                }
            }
            Err(e) => tracing::debug!("🐝 SWARM [C2Operator]: Operador falló verificación: {}", e),
        }
    }

    tracing::warn!("⚠️ SWARM [C2Operator]: No se pudo establecer persistencia con ningún operador disponible.");
    let mut sink_target = target.clone();
    sink_target.findings = Arc::new(vec![finding]);
    let _ = sink_tx.send(sink_target).await;
    Ok(())
}

pub async fn execute_reporter(
    finding: Finding,
    target: &TargetHost,
    sink_tx: &mpsc::Sender<TargetHost>,
    guard: TokenGuard,
) -> Result<()> {
    tracing::debug!("📝 SWARM [Reporter]: Archivando hallazgo informativo: {}", finding.core.title);
    guard.commit(0);
    let mut sink_target = target.clone();
    sink_target.findings = Arc::new(vec![finding]);
    let _ = sink_tx.send(sink_target).await;
    Ok(())
}

impl<M: ExecutorMode> SwarmOrchestrator<M> {
    pub(crate) async fn plan_next_step(&self, finding: &Finding, target: &TargetHost) -> Result<AgentRole> {
        let _compressed = crate::core::ai::ContextCompressor::compress_swarm_context(finding, target);
        
        let level = if finding.core.severity == Severity::Critical { RouteLevel::Premium } else { RouteLevel::Mid };
        tracing::info!("🐝 SWARM [Planner]: Routing {} to {:?} tier.", finding.core.id, level);
        
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

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn process_finding(
        &self,
        finding: Finding,
        seen_finding_ids: &mut HashSet<String>,
        correlation_engine: &Arc<tokio::sync::Mutex<crate::core::correlation::CorrelationEngine>>,
        fired_chains: &Arc<dashmap::DashSet<String>>,
        inventory: &Arc<crate::core::orchestrator::swarm::inventory::SwarmInventory>,
        discovery_tx: &mpsc::Sender<Finding>,
        join_set: &mut tokio::task::JoinSet<Result<()>>,
        agent_semaphore: &Arc<tokio::sync::Semaphore>,
        jitter: &Arc<EvasionJitter>,
        adaptive_context: &AdaptiveContext,
        initial_target: &TargetHost,
        sink_tx: &mpsc::Sender<TargetHost>,
    ) -> Result<()> {
        if seen_finding_ids.contains(&finding.core.id) { return Ok(()); }
        seen_finding_ids.insert(finding.core.id.clone());
        
        let critical_paths_to_emit: Vec<crate::models::Finding> = {
            let mut ce = correlation_engine.lock().await;
            super::correlation::process_correlation(&mut ce, &finding, &initial_target.scope_id, seen_finding_ids)
        };

        let mut is_on_critical_path = false;
        for path_finding in &critical_paths_to_emit {
            tracing::info!("🔱 V14.1 SOVEREIGN: Critical Attack Path discovered! Injecting finding into swarm.");
            let _ = discovery_tx.send(path_finding.clone()).await;
            
            if path_finding.evidence.primary.as_ref()
                .and_then(|e| e.data.get("nodes"))
                .and_then(|n| n.as_array())
                .map(|nodes| nodes.iter().any(|nid| nid.as_str() == Some(&finding.core.id)))
                .unwrap_or(false) 
            {
                is_on_critical_path = true;
            }
        }

        inventory.ingest_finding(finding.clone(), crate::core::orchestrator::swarm::inventory::TrustLevel::Private);

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

        let mut role = self.plan_next_step(&finding, initial_target).await?;
        
        if is_on_critical_path && finding.core.category == Category::Vulnerability {
            tracing::info!("🔱 V14.1 SOVEREIGN: High-value AD path detected! Prioritizing pivot for {}.", finding.core.id);
            role = AgentRole::Exploiter;
        }

        let attack_context = {
            let mut ce_handle = correlation_engine.lock().await;
            ce_handle.get_context_summary(&finding.core.id)
        };
        tracing::debug!("🐝 SWARM [Planner]: Asignando hallazgo {} al agente {:?}", finding.core.id, role);

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
                tracing::warn!("💸 SWARM: No hay presupuesto suficiente para spawnear agente {:?} (Hallazgo {}). Skipping.", role, finding.core.id);
                return Ok(());
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
                    tracing::warn!("🛡️ SWARM: CRITICAL BUDGET LIMIT! Tokens > 95%. Forcing emergency pivot to Passive Reporter for {}.", finding_id);
                    return execute_reporter(finding_clone, &target_clone, &sink_tx_clone, guard).await;
                }

                match role {
                    AgentRole::Scout => execute_scout(&*orchestrator, AgentTask::<M> {
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
                    AgentRole::Exploiter => execute_exploiter(&*orchestrator, AgentTask::<M> {
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
                    AgentRole::C2Operator => execute_c2_operator(
                        &*orchestrator,
                        finding_clone, 
                        &target_clone, 
                        &mut ctx_clone, 
                        &sink_tx_clone, 
                        guard,
                        jitter_task.clone()
                    ).await,
                    AgentRole::GhostReporter => execute_reporter(finding_clone, &target_clone, &sink_tx_clone, guard).await,
                    AgentRole::Planner => {
                        let mut ce = ce_clone.lock().await;
                        crate::core::correlation::ingestor::Ingestor::ingest_finding(&mut ce, finding_clone);
                        guard.commit(0);
                        Ok(())
                    },
                }
            }).catch_unwind().await;

            match result {
                Ok(res) => res,
                Err(_) => {
                    tracing::error!("🛑 SWARM CRITICAL: Agent {:?} for finding {} caught a PANIC. Isolating.", role, finding_id);
                    anyhow::bail!("Agent panicked")
                }
            }
        });

        Ok(())
    }
}
