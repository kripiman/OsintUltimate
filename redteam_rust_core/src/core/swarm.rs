use crate::models::{Finding, TargetHost, Category, Severity, AIAnalysis};
use crate::core::pipeline::Pipeline;
use crate::core::ai_cascade::{TieredAIRouter, AdaptiveContext, RouteLevel};
use crate::core::approval_gate::ApprovalGate;
use anyhow::{Result, Context};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{info, warn, error, debug};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::atomic::{AtomicU32, Ordering};

// ─────────────────────────────────────────────────────────────────────────────
// TOKEN BUDGET & COST CONTROL
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct TokenBudget {
    pub prompt_tokens: AtomicU32,
    pub completion_tokens: AtomicU32,
    pub total_tokens: AtomicU32,
    pub reserved_tokens: AtomicU32,
    pub max_tokens: u32,
}

impl TokenBudget {
    pub fn new(max: u32) -> Self {
        // V12 HARDENING (HIGH-002): Zero-budget prevention.
        // If 0 is provided, we set a default safe floor (50k tokens) to prevent infinite loops.
        let safe_max = if max == 0 { 50_000 } else { max };
        Self {
            max_tokens: safe_max,
            ..Default::default()
        }
    }

    pub fn add_usage(&self, usage: &crate::models::findings::TokenUsage) {
        self.prompt_tokens.fetch_add(usage.prompt_tokens, Ordering::SeqCst);
        self.completion_tokens.fetch_add(usage.completion_tokens, Ordering::SeqCst);
        self.total_tokens.fetch_add(usage.total_tokens, Ordering::SeqCst);
    }

    /// Pre-reserve tokens before a long-running AI call to prevent over-spending
    pub fn reserve_tokens(&self, amount: u32) -> bool {
        // V12 HARDENING: No more bypass if max_tokens == 0 (handled in constructor)
        let current = self.total_tokens.load(Ordering::SeqCst);
        let reserved = self.reserved_tokens.load(Ordering::SeqCst);
        
        if current + reserved + amount > self.max_tokens {
            warn!("🛑 SWARM BUDGET EXHAUSTED: Attempted to reserve {} tokens (Current: {}, Reserved: {}, Max: {})", 
                  amount, current, reserved, self.max_tokens);
            return false;
        }
        
        self.reserved_tokens.fetch_add(amount, Ordering::SeqCst);
        true
    }

    /// Commit actual usage and release reservation
    pub fn commit_usage(&self, actual: u32, reserved: u32) {
        self.total_tokens.fetch_add(actual, Ordering::Relaxed);
        self.reserved_tokens.fetch_sub(reserved, Ordering::Relaxed);
    }

    pub fn is_exhausted(&self) -> bool {
        // V12 HARDENING: Strict budget enforcement (no zero-bypass)
        (self.total_tokens.load(Ordering::SeqCst) + self.reserved_tokens.load(Ordering::SeqCst)) >= self.max_tokens
    }

    pub fn current_total(&self) -> u32 {
        self.total_tokens.load(Ordering::Relaxed)
    }

    pub fn current_effective_total(&self) -> u32 {
        self.total_tokens.load(Ordering::Relaxed) + self.reserved_tokens.load(Ordering::Relaxed)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SWARM AGENT ROLES
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentRole {
    Planner,
    Scout,
    Exploiter,
    GhostReporter,
}

// ─────────────────────────────────────────────────────────────────────────────
// SWARM ORCHESTRATOR
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct SwarmOrchestrator {
    router: Arc<TieredAIRouter>,
    pipeline: Arc<Pipeline>,
    approval_gate: Arc<ApprovalGate>,
    budget: Arc<TokenBudget>,
    operator: crate::core::approval_gate::User,
}

impl SwarmOrchestrator {
    pub fn new(
        router: Arc<TieredAIRouter>,
        pipeline: Arc<Pipeline>,
        approval_gate: Arc<ApprovalGate>,
        max_tokens: u32,
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
        }
    }

    pub fn clone_for_spawn(&self) -> Self {
        self.clone()
    }

    pub async fn run(&self, initial_target: TargetHost, sink_tx: mpsc::Sender<TargetHost>) -> Result<()> {
        info!("🐝 SWARM: Iniciando enjambre multi-agente para {}", initial_target.host);
        
        let mut seen_finding_ids = HashSet::new();
        let mut adaptive_context = AdaptiveContext::default();
        let mut correlation_engine = crate::core::CorrelationEngine::new();
        
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

        while let Some(finding) = discovery_rx.recv().await {
            if self.budget.is_exhausted() {
                warn!("💸 SWARM: Presupuesto de tokens agotado ({}). Deteniendo enjambre.", self.budget.current_total());
                break;
            }

            if seen_finding_ids.contains(&finding.id) { continue; }
            seen_finding_ids.insert(finding.id.clone());
            correlation_engine.add_finding(finding.clone());

            // 1. PLANNER: Decision de ruteo
            let role = self.plan_next_step(&finding, &initial_target).await?;
            debug!("🐝 SWARM [Planner]: Asignando hallazgo {} al agente {:?}", finding.id, role);

            // 2. AGENT EXECUTION (ARCH-02: Concurrent Agent Execution)
            let orchestrator = Arc::new(self.clone_for_spawn()); 
            let finding_clone = finding.clone();
            let target_clone = initial_target.clone();
            let mut scout_tx = discovery_tx.clone();
            let mut ctx_clone = adaptive_context.clone();
            let sink_tx_clone = sink_tx.clone();
            let semaphore = agent_semaphore.clone();

            // Optimistic Reservation: 1000 tokens per agent estimate
            if !self.budget.reserve_tokens(1000) {
                warn!("💸 SWARM: No hay presupuesto suficiente para spawnear agente para hallazgo {}. Skipping.", finding.id);
                continue;
            }

            join_set.spawn(async move {
                let _permit = semaphore.acquire().await.ok();
                let res = match role {
                    AgentRole::Scout => orchestrator.execute_scout(finding_clone, &target_clone, &mut scout_tx, &mut ctx_clone, &sink_tx_clone).await,
                    AgentRole::Exploiter => orchestrator.execute_exploiter(finding_clone, &target_clone, &mut scout_tx, &mut ctx_clone, &sink_tx_clone).await,
                    AgentRole::GhostReporter => orchestrator.execute_reporter(finding_clone, &target_clone, &sink_tx_clone).await,
                    AgentRole::Planner => Ok(()),
                };
                
                // V12 FIX: Ensure reservation is ALWAYS cleared if not consumed by the agent's logic.
                // commit_usage(0, 1000) effectively releases the 1000 reserved tokens.
                if let AgentRole::GhostReporter | AgentRole::Planner = role {
                     orchestrator.budget.commit_usage(0, 1000); 
                }
                res
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
        let _compressed = crate::core::ai_cascade::ContextCompressor::compress_swarm_context(finding, target);
        
        // En v4 el Planner usa Gemini Flash (Mid) o Local por defecto para ahorrar tokens.
        // Solo si el hallazgo es crítico escalamos a Premium.
        let level = if finding.severity == Severity::Critical { RouteLevel::Premium } else { RouteLevel::Mid };
        
        // Lógica simplificada: 
        // Recon/Port -> Scout
        // Vulnerality/Misconfig -> Exploiter
        // Otros -> Reporter
        match finding.category {
            Category::Recon | Category::NetworkPort | Category::TechnologyStack => Ok(AgentRole::Scout),
            Category::Vulnerability | Category::Misconfiguration | Category::CredentialLeak => Ok(AgentRole::Exploiter),
            _ => Ok(AgentRole::GhostReporter),
        }
    }

    async fn execute_scout(
        &self,
        finding: Finding,
        target: &TargetHost,
        tx: &mut mpsc::Sender<Finding>,
        adaptive_ctx: &mut AdaptiveContext,
        sink_tx: &mpsc::Sender<TargetHost>,
    ) -> Result<()> {
        info!("🔍 SWARM [Scout]: Profundizando en hallazgo de infraestructura: {}", finding.title);
        
        // El Scout usa el Router para decidir qué herramienta de enumeración usar
        let metadata = self.pipeline.get_plugin_metadata();
        match self.router.decide_action(&finding, target, &metadata, Some(adaptive_ctx)).await {
            Ok(Some((action, tactical))) => {
                // V12: Commit usage from decide_action (which calls the AI)
                // Note: decide_action should provide usage in the next iteration of the API.
                // For now, we commit 200 tokens as a reasonable average for a Flash-level decision.
                self.budget.commit_usage(200, 1000); 

                let mut task_target = target.clone();
                task_target.tactical_context = Arc::new(tactical);
                
                let results = self.pipeline.run_specific_plugin(&action, &task_target).await?;
                for nf in results {
                    let _ = tx.send(nf).await;
                }
            }
            Ok(None) => {
                self.budget.commit_usage(0, 1000); // Release reservation
            }
            Err(e) => {
                self.budget.commit_usage(0, 1000); // Release reservation
                return Err(e);
            }
        }
        
        // Reportar hallazgo inicial procesado
        let mut sink_target = target.clone();
        sink_target.findings = Arc::new(vec![finding]);
        let _ = sink_tx.send(sink_target).await;
        
        Ok(())
    }

    async fn execute_exploiter(
        &self,
        mut finding: Finding,
        target: &TargetHost,
        tx: &mut mpsc::Sender<Finding>,
        adaptive_ctx: &mut AdaptiveContext,
        sink_tx: &mpsc::Sender<TargetHost>,
    ) -> Result<()> {
        info!("💥 SWARM [Exploiter]: Intentando validación/explotación de: {}", finding.title);
        
        // 1. Análisis Premium para generación de PoC
        match self.router.analyze(&finding, target).await {
            Ok(analysis) => {
                self.budget.commit_usage(analysis.usage.total_tokens, 1000); // Commit against reservation
                finding = finding.with_ai_analysis(analysis.clone());
                
                // 2. Validación de PoC (PocValidator se encarga de aprobaciones)
                let poc_validator = crate::core::poc_validator::PocValidator::new(
                    self.router.clone(),
                    self.approval_gate.clone(),
                    self.operator.clone(),
                );
                
                if analysis.risk_score >= 7 {
                    let _ = poc_validator.validate(&mut finding, target).await;
                }
            }
            Err(e) => {
                self.budget.commit_usage(0, 1000); // Release reservation on error
                warn!("⚠️ SWARM [Exploiter]: Error en análisis de explotación: {}", e);
            }
        }

        // Reportar
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
    ) -> Result<()> {
        debug!("📝 SWARM [Reporter]: Archivando hallazgo informativo: {}", finding.title);
        let mut sink_target = target.clone();
        sink_target.findings = Arc::new(vec![finding]);
        let _ = sink_tx.send(sink_target).await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_budget_reservation() {
        let budget = TokenBudget::new(5000);
        
        // Reserve 2000 - should succeed
        assert!(budget.reserve_tokens(2000));
        assert_eq!(budget.current_effective_total(), 2000);
        
        // Reserve another 2000 - should succeed
        assert!(budget.reserve_tokens(2000));
        assert_eq!(budget.current_effective_total(), 4000);
        
        // Reserve 1500 - should fail (4000 + 1500 > 5000)
        assert!(!budget.reserve_tokens(1500));
        assert_eq!(budget.current_effective_total(), 4000);
    }

    #[test]
    fn test_token_budget_commitment() {
        let budget = TokenBudget::new(5000);
        budget.reserve_tokens(1000);
        
        // Commit 800 tokens, releasing 1000 reservation
        budget.commit_usage(800, 1000);
        
        assert_eq!(budget.current_total(), 800);
        assert_eq!(budget.current_effective_total(), 800);
        assert_eq!(budget.reserved_tokens.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_token_budget_exhaustion() {
        let budget = TokenBudget::new(1000);
        budget.reserve_tokens(900);
        assert!(!budget.is_exhausted());
        
        budget.reserve_tokens(100);
        assert!(budget.is_exhausted());
    }
}
