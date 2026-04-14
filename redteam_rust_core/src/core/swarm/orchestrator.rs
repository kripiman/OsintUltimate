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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentRole {
    Planner,
    Scout,
    Exploiter,
    C2Operator,
    GhostReporter,
}

#[derive(Clone)]
pub struct SwarmOrchestrator<M: ExecutorMode = crate::utils::executor::GhostMode> {
    pub router: Arc<TieredAIRouter>,
    pub pipeline: Arc<Pipeline<M>>,
    pub approval_gate: Arc<ApprovalGate>,
    pub budget: Arc<TokenBudget>,
    pub operator: crate::core::approval_gate::User,
    pub proxy_manager: Option<Arc<crate::utils::proxy::ProxyManager>>,
    pub executor: Arc<StealthExecutor<M>>,
    pub policy: Arc<dyn crate::core::policy::PolicyProvider>,
}

impl<M: ExecutorMode> SwarmOrchestrator<M> {
    pub fn new(
        router: Arc<TieredAIRouter>,
        pipeline: Arc<Pipeline<M>>,
        approval_gate: Arc<ApprovalGate>,
        max_tokens: u32,
        proxy_manager: Option<Arc<crate::utils::proxy::ProxyManager>>,
        executor: Arc<StealthExecutor<M>>,
        policy: Arc<dyn crate::core::policy::PolicyProvider>,
    ) -> Self {
        let operator = crate::core::approval_gate::User {
            id: "swarm-orchestrator".to_string(),
            name: "Osint-Swarm".to_string(),
            role: crate::core::approval_gate::UserRole::RedTeamFull,
            authorized_at: chrono::Utc::now(),
        };
        Self {
            router,
            pipeline,
            approval_gate,
            budget: Arc::new(TokenBudget::new(max_tokens)),
            operator,
            proxy_manager,
            executor,
            policy,
        }
    }

    pub fn clone_for_spawn(&self) -> Self {
        self.clone()
    }

    pub async fn run(&self, initial_target: TargetHost, sink_tx: mpsc::Sender<TargetHost>) -> Result<()> {
        info!("🐝 SWARM: Iniciando enjambre multi-agente para {}", initial_target.host);
        
        // 🔱 V14.1 READINESS GATE (Professional Grade)
        if let Some(ref pm) = self.proxy_manager {
            info!("⏳ SWARM: Verificando integridad de egreso (ProxyManager readiness)...");
            pm.wait_for_readiness(std::time::Duration::from_secs(30))
                .await
                .context("V14.1 OPSEC Block: Swarm cannot start without healthy egress proxies.")?;
            info!("✅ SWARM: Egress verificado. Sparking the swarm.");
        }
        
        let mut seen_finding_ids = HashSet::new();
        let adaptive_context = AdaptiveContext::default();
        let correlation_engine = Arc::new(tokio::sync::Mutex::new(crate::core::correlation::CorrelationEngine::new()));
        
        let (discovery_tx, mut discovery_rx) = mpsc::channel(100);
        let pipeline = self.pipeline.clone();
        let target = initial_target.clone();
        
        // FASE 1: SCOUT - Discovery inicial
        let pipeline_clone = pipeline.clone();
        let discovery_tx_clone = discovery_tx.clone();
        tokio::spawn(async move {
            let _ = pipeline_clone.run_discovery(&target, discovery_tx_clone).await;
        });

        let mut join_set = tokio::task::JoinSet::new();
        // V12 HARDENING (HIGH-002): Concurrent Agent Limit (DoS prevention)
        let agent_semaphore = Arc::new(tokio::sync::Semaphore::new(10));
        let max_pending_tasks = 50; // V12 FIX (HIGH-001): Limit JoinSet size to prevent DoS

        while let Some(finding) = discovery_rx.recv().await {
            // V12 FIX: Limit JoinSet size to prevent DoS (HIGH-001)
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

            if seen_finding_ids.contains(&finding.id) { continue; }
            seen_finding_ids.insert(finding.id.clone());
            {
                let mut ce = correlation_engine.lock().await;
                ce.add_finding(finding.clone());
            }

            let mut role = self.plan_next_step(&finding, &initial_target).await?;
            
            let ce_handle = correlation_engine.lock().await;
            let paths = ce_handle.get_attack_paths();
            if let Some(da_path) = paths.iter().find(|p| p.description.contains("Windows") && p.total_cvss > 0.8) {
                info!("🔱 V14.1 SOVEREIGN: High-value AD path detected! Prioritizing pivot: {}", da_path.description);
                if da_path.nodes.contains(&finding.id) && finding.category == Category::Vulnerability {
                    role = AgentRole::Exploiter;
                }
            }
            let attack_context = ce_handle.get_context_summary(&finding.id);
            debug!("🐝 SWARM [Planner]: Asignando hallazgo {} al agente {:?}", finding.id, role);

            // 2. AGENT EXECUTION (ARCH-02: Concurrent Agent Execution)
            let orchestrator = Arc::new(self.clone_for_spawn()); 
            let finding_clone = finding.clone();
            let target_clone = initial_target.clone();
            let mut scout_tx = discovery_tx.clone();
            let mut ctx_clone = adaptive_context.clone();
            let ce_clone = correlation_engine.clone();
            let sink_tx_clone = sink_tx.clone();
            let semaphore = agent_semaphore.clone();

            // V12 HARDENING: Use TokenGuard for RAII-based reservation
            let priority = match role {
                AgentRole::Planner => TaskPriority::High,
                AgentRole::Exploiter => TaskPriority::Normal,
                _ => TaskPriority::Low,
            };

            let guard = match TokenGuard::new(self.budget.clone(), 1000, priority) {
                Some(g) => g,
                None => {
                    warn!("💸 SWARM: No hay presupuesto suficiente para spawnear agente {:?} (Hallazgo {}). Skipping.", role, finding.id);
                    continue;
                }
            };

            join_set.spawn(async move {
                let _permit = semaphore.acquire().await.ok();
                // PFC-001/V12: Agent isolation via RAII and Panic handling
                
                // V13 HARDENING: Explicit catch_unwind to prevent any state leakage from panicked agents.
                use std::panic::AssertUnwindSafe;
                use futures::FutureExt;

                let finding_id = finding_clone.id.clone();
                let result = AssertUnwindSafe(async {
                    // V13: Strategic Pivot Check (Professional Egress Management)
                    if orchestrator.budget.current_effective_total() > (orchestrator.budget.max_tokens as f64 * 0.95) as u32 
                       && role != AgentRole::GhostReporter {
                        warn!("🛡️ SWARM: CRITICAL BUDGET LIMIT! Tokens > 95%. Forcing emergency pivot to Passive Reporter for {}.", finding_id);
                        return orchestrator.execute_reporter(finding_clone, &target_clone, &sink_tx_clone, guard).await;
                    }

                    match role {
                        AgentRole::Scout => orchestrator.execute_scout(finding_clone, &target_clone, attack_context, &mut scout_tx, &mut ctx_clone, &sink_tx_clone, guard).await,
                        AgentRole::Exploiter => orchestrator.execute_exploiter(finding_clone, &target_clone, attack_context, &mut scout_tx, &mut ctx_clone, &sink_tx_clone, guard).await,
                        AgentRole::C2Operator => orchestrator.execute_c2_operator(finding_clone, &target_clone, &mut ctx_clone, &sink_tx_clone, guard).await,
                        AgentRole::GhostReporter => orchestrator.execute_reporter(finding_clone, &target_clone, &sink_tx_clone, guard).await,
                        AgentRole::Planner => {
                            // Planner agents can now update the shared engine directly
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
        
        // Wait for all agents to finish
        // V12 HARDENING: Robust Agent Join and Error Reporting
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
        Ok(())
    }

    async fn plan_next_step(&self, finding: &Finding, target: &TargetHost) -> Result<AgentRole> {
        // V10: Use aggressive compression for planning to save tokens
        let _compressed = crate::core::ai::ContextCompressor::compress_swarm_context(finding, target);
        
        // En v4 el Planner usa Gemini Flash (Mid) o Local por defecto para ahorrar tokens.
        // Solo si el hallazgo es crítico escalamos a Premium.
        let level = if finding.severity == Severity::Critical { RouteLevel::Premium } else { RouteLevel::Mid };
        info!("🐝 SWARM [Planner]: Routing {} to {:?} tier.", finding.id, level);
        
        // Lógica simplificada: 
        // Recon/Port -> Scout
        // Vulnerality/Misconfig -> Exploiter
        // Otros -> Reporter
        match finding.category {
            Category::Recon | Category::NetworkPort | Category::TechnologyStack => Ok(AgentRole::Scout),
            Category::Vulnerability | Category::Misconfiguration | Category::CredentialLeak => {
                // Si ya está verificado, pasar a C2
                if finding.evidence.verified && finding.severity >= Severity::High {
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
        finding: Finding,
        target: &TargetHost,
        attack_context: Option<String>,
        tx: &mut mpsc::Sender<Finding>,
        adaptive_ctx: &mut AdaptiveContext,
        sink_tx: &mpsc::Sender<TargetHost>,
        guard: TokenGuard,
    ) -> Result<()> {
        info!("🔍 SWARM [Scout]: Profundizando en hallazgo de infraestructura: {}", finding.title);
        
        let metadata = self.pipeline.get_plugin_metadata();
        match self.router.decide_action(&finding, target, &metadata, attack_context.as_deref(), Some(adaptive_ctx)).await {
            Ok(Some((action, tactical))) => {
                // V12: Commit usage and transition guard
                guard.commit(200); 

                let mut task_target = target.clone();
                task_target.tactical_context = Arc::new(tactical);
                
                let results = self.pipeline.run_specific_plugin(&action, &task_target).await?;
                for nf in results {
                    let _ = tx.send(nf).await;
                }
            }
            Ok(None) => {
                // Guard will auto-release on drop if not committed
            }
            Err(e) => {
                return Err(e);
            }
        }
        
        let mut sink_target = target.clone();
        sink_target.findings = Arc::new(vec![finding]);
        let _ = sink_tx.send(sink_target).await;
        
        Ok(())
    }

    async fn execute_exploiter(
        &self,
        mut finding: Finding,
        target: &TargetHost,
        attack_context: Option<String>,
        _tx: &mut mpsc::Sender<Finding>,
        adaptive_ctx: &mut AdaptiveContext,
        sink_tx: &mpsc::Sender<TargetHost>,
        guard: TokenGuard,
    ) -> Result<()> {
        info!("💥 SWARM [Exploiter]: Intentando validación/explotación de: {} [Posture: STRIKE]", finding.title);
        
        // V14: Elevate to STRIKE posture during active exploitation
        adaptive_ctx.posture = crate::core::ai::Posture::Strike;
        
        match self.router.analyze(&finding, target, attack_context.as_deref()).await {
            Ok(analysis) => {
                let usage = analysis.usage.total_tokens;
                guard.commit(usage); 
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
                    let _ = poc_validator.validate(&mut finding, target, attack_context.as_deref()).await;
                }
            }
            Err(e) => {
                warn!("⚠️ SWARM [Exploiter]: Error en análisis de explotación: {}", e);
            }
        }

        let mut sink_target = target.clone();
        sink_target.findings = Arc::new(vec![finding]);
        let _ = sink_tx.send(sink_target).await;

        Ok(())
    }

    async fn execute_c2_operator(
        &self,
        finding: Finding,
        target: &TargetHost,
        adaptive_ctx: &mut AdaptiveContext,
        sink_tx: &mpsc::Sender<TargetHost>,
        guard: TokenGuard,
    ) -> Result<()> {
        info!("🔱 SWARM [C2Operator]: Orquestando persistencia dinámica para {} [Posture: BREACH]", target.host);
        
        // V14: Elevate to BREACH posture during post-exploitation
        adaptive_ctx.posture = crate::core::ai::Posture::Breach;
        
        guard.commit(500);

        // V14.1: Delegación al trait en lugar de hardcodear plugins
        let operators = self.pipeline.get_c2_operators();
        if operators.is_empty() {
             warn!("⚠️ SWARM [C2Operator]: No se encontraron operadores C2 cargados en la pipeline.");
        }

        for c2 in operators {
            // El orquestador ahora solo maneja el flujo de estados C2 (Routing)
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
                        
                        // Generar hallazgo de persistencia para el sink
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
        debug!("📝 SWARM [Reporter]: Archivando hallazgo informativo: {}", finding.title);
        guard.commit(0);
        let mut sink_target = target.clone();
        sink_target.findings = Arc::new(vec![finding]);
        let _ = sink_tx.send(sink_target).await;
        Ok(())
    }
}
