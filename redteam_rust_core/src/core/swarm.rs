use crate::models::{Finding, TargetHost, Category, Severity, AIAnalysis};
use crate::core::pipeline::Pipeline;
use crate::core::ai::{TieredAIRouter, AdaptiveContext, RouteLevel};
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
    pub max_per_agent: u32,
    pub priority_boost: AtomicU32, // Reserved for high-priority tasks
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskPriority {
    High, // Planner
    Normal, // Exploiter
    Low, // Scout/Reporter
}

impl TokenBudget {
    pub fn new(max: u32) -> Self {
        let safe_max = if max == 0 { 50_000 } else { max };
        Self {
            max_tokens: safe_max,
            max_per_agent: safe_max / 2, // Default to 50% of budget per agent
            ..Default::default()
        }
    }

    pub fn with_max_per_agent(mut self, max_per_agent: u32) -> Self {
        self.max_per_agent = max_per_agent;
        self
    }

    pub fn add_usage(&self, usage: &crate::models::findings::TokenUsage) {
        self.prompt_tokens.fetch_add(usage.prompt_tokens, Ordering::Relaxed);
        self.completion_tokens.fetch_add(usage.completion_tokens, Ordering::Relaxed);
        self.total_tokens.fetch_add(usage.total_tokens, Ordering::Relaxed);
    }

    /// V12 HARDENING: Race-condition safe reservation using atomic compare_exchange.
    pub fn reserve_tokens(&self, amount: u32, priority: TaskPriority) -> bool {
        let mut current_reserved = self.reserved_tokens.load(Ordering::SeqCst);
        loop {
            let total = self.total_tokens.load(Ordering::SeqCst);
            
            // V13 HARDENING: Priority-based admission control
            let threshold = match priority {
                TaskPriority::High => self.max_tokens, // High priority can use full budget
                TaskPriority::Normal => (self.max_tokens as f64 * 0.95) as u32, // Normal capped at 95%
                TaskPriority::Low => (self.max_tokens as f64 * 0.85) as u32, // Low capped at 85%
            };

            if total + current_reserved + amount > threshold {
                return false;
            }
            match self.reserved_tokens.compare_exchange_weak(
                current_reserved,
                current_reserved + amount,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => return true,
                Err(new_val) => current_reserved = new_val,
            }
        }
    }

    pub fn release_reservation(&self, amount: u32) {
        self.reserved_tokens.fetch_sub(amount, Ordering::SeqCst);
    }

    pub fn commit_usage(&self, actual: u32, reserved: u32) {
        self.total_tokens.fetch_add(actual, Ordering::SeqCst);
        self.reserved_tokens.fetch_sub(reserved, Ordering::SeqCst);
    }

    pub fn is_exhausted(&self) -> bool {
        (self.total_tokens.load(Ordering::SeqCst) + self.reserved_tokens.load(Ordering::SeqCst)) >= self.max_tokens
    }

    pub fn current_total(&self) -> u32 {
        self.total_tokens.load(Ordering::Relaxed)
    }

    pub fn current_effective_total(&self) -> u32 {
        self.total_tokens.load(Ordering::Relaxed) + self.reserved_tokens.load(Ordering::Relaxed)
    }
}

/// V12 HARDENING: RAII Guard to ensure tokens are released even if an agent panics.
pub struct TokenGuard {
    budget: Arc<TokenBudget>,
    amount: u32,
    active: bool,
}

impl TokenGuard {
    pub fn new(budget: Arc<TokenBudget>, amount: u32, priority: TaskPriority) -> Option<Self> {
        // V13 HARDENING: Enforce per-agent limits
        let safe_amount = if amount > budget.max_per_agent {
            warn!("💸 SWARM: Requested tokens ({}) exceeds per-agent limit ({}). Capping.", amount, budget.max_per_agent);
            budget.max_per_agent
        } else {
            amount
        };

        if budget.reserve_tokens(safe_amount, priority) {
            Some(Self { budget, amount: safe_amount, active: true })
        } else {
            None
        }
    }

    pub fn commit(mut self, actual: u32) {
        self.budget.commit_usage(actual, self.amount);
        self.active = false;
    }
}

impl Drop for TokenGuard {
    fn drop(&mut self) {
        if self.active {
            warn!("💸 SWARM: TokenGuard dropped without commitment. Releasing {} reserved tokens.", self.amount);
            self.budget.release_reservation(self.amount);
        }
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
    proxy_manager: Option<Arc<crate::utils::proxy::ProxyManager>>,
}

impl SwarmOrchestrator {
    pub fn new(
        router: Arc<TieredAIRouter>,
        pipeline: Arc<Pipeline>,
        approval_gate: Arc<ApprovalGate>,
        max_tokens: u32,
        proxy_manager: Option<Arc<crate::utils::proxy::ProxyManager>>,
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
                // V13: Strategic Pivot Check
                if orchestrator.budget.current_effective_total() > (orchestrator.budget.max_tokens as f64 * 0.98) as u32 
                   && role != AgentRole::GhostReporter {
                    warn!("🛡️ SWARM: EMERGENCY PIVOT! Budget nearly exhausted. Transitioning to Passive Reporter for {}.", finding_clone.id);
                    return orchestrator.execute_reporter(finding_clone, &target_clone, &sink_tx_clone, guard).await;
                }

                let res = match role {
                    AgentRole::Scout => orchestrator.execute_scout(finding_clone, &target_clone, &mut scout_tx, &mut ctx_clone, &sink_tx_clone, guard).await,
                    AgentRole::Exploiter => orchestrator.execute_exploiter(finding_clone, &target_clone, &mut scout_tx, &mut ctx_clone, &sink_tx_clone, guard).await,
                    AgentRole::GhostReporter => orchestrator.execute_reporter(finding_clone, &target_clone, &sink_tx_clone, guard).await,
                    AgentRole::Planner => {
                        guard.commit(0);
                        Ok(())
                    },
                };
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
        let _compressed = crate::core::ai::ContextCompressor::compress_swarm_context(finding, target);
        
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
        guard: TokenGuard,
    ) -> Result<()> {
        info!("🔍 SWARM [Scout]: Profundizando en hallazgo de infraestructura: {}", finding.title);
        
        let metadata = self.pipeline.get_plugin_metadata();
        match self.router.decide_action(&finding, target, &metadata, Some(adaptive_ctx)).await {
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
        tx: &mut mpsc::Sender<Finding>,
        _adaptive_ctx: &mut AdaptiveContext,
        sink_tx: &mpsc::Sender<TargetHost>,
        guard: TokenGuard,
    ) -> Result<()> {
        info!("💥 SWARM [Exploiter]: Intentando validación/explotación de: {}", finding.title);
        
        match self.router.analyze(&finding, target).await {
            Ok(analysis) => {
                let usage = analysis.usage.total_tokens;
                guard.commit(usage); 
                finding = finding.with_ai_analysis(analysis.clone());
                
                let poc_validator = crate::core::poc_validator::PocValidator::new(
                    self.router.clone(),
                    self.approval_gate.clone(),
                    self.operator.clone(),
                    self.proxy_manager.clone(),
                );
                
                if analysis.risk_score >= 7 {
                    let _ = poc_validator.validate(&mut finding, target).await;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_budget_reservation() {
        let budget = TokenBudget::new(5000);
        
        // Reserve 2000 - should succeed
        assert!(budget.reserve_tokens(2000, TaskPriority::High));
        assert_eq!(budget.current_effective_total(), 2000);
        
        // Reserve another 2000 - should succeed
        assert!(budget.reserve_tokens(2000, TaskPriority::High));
        assert_eq!(budget.current_effective_total(), 4000);
        
        // Reserve 1500 - should fail (4000 + 1500 > 5000)
        assert!(!budget.reserve_tokens(1500, TaskPriority::High));
        assert_eq!(budget.current_effective_total(), 4000);
    }

    #[test]
    fn test_token_budget_commitment() {
        let budget = TokenBudget::new(5000);
        budget.reserve_tokens(1000, TaskPriority::Normal);
        
        // Commit 800 tokens, releasing 1000 reservation
        budget.commit_usage(800, 1000);
        
        assert_eq!(budget.current_total(), 800);
        assert_eq!(budget.current_effective_total(), 800);
        assert_eq!(budget.reserved_tokens.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_token_budget_exhaustion() {
        let budget = TokenBudget::new(1000);
        budget.reserve_tokens(900, TaskPriority::High);
        assert!(!budget.is_exhausted());
        
        budget.reserve_tokens(100, TaskPriority::High);
        assert!(budget.is_exhausted());
    }

    #[test]
    fn test_token_budget_per_agent_limit() {
        let budget = Arc::new(TokenBudget::new(10000).with_max_per_agent(1000));
        
        // Requesting 500 should succeed and stay 500
        let guard1 = TokenGuard::new(budget.clone(), 500, TaskPriority::High).unwrap();
        assert_eq!(guard1.amount, 500);
        
        // Requesting 2000 should be capped to 1000
        let guard2 = TokenGuard::new(budget.clone(), 2000, TaskPriority::High).unwrap();
        assert_eq!(guard2.amount, 1000);
    }
}
