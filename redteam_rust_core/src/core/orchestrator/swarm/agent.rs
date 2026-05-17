use crate::models::{Finding, TargetHost};
use crate::core::orchestrator::swarm::budget::TokenGuard;
use crate::plugins::detection_evasion::jitter::EvasionJitter;
use crate::utils::executor::ExecutorMode;
use std::sync::Arc;
use tokio::sync::mpsc;

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
