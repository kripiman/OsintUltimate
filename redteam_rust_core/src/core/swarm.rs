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
    pub max_tokens: u32,
}

impl TokenBudget {
    pub fn new(max: u32) -> Self {
        Self {
            max_tokens: max,
            ..Default::default()
        }
    }

    pub fn add_usage(&self, usage: &crate::models::findings::TokenUsage) {
        self.prompt_tokens.fetch_add(usage.prompt_tokens, Ordering::Relaxed);
        self.completion_tokens.fetch_add(usage.completion_tokens, Ordering::Relaxed);
        self.total_tokens.fetch_add(usage.total_tokens, Ordering::Relaxed);
    }

    pub fn is_exhausted(&self) -> bool {
        if self.max_tokens == 0 { return false; }
        self.total_tokens.load(Ordering::Relaxed) >= self.max_tokens
    }

    pub fn current_total(&self) -> u32 {
        self.total_tokens.load(Ordering::Relaxed)
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

    pub async fn run(&self, initial_target: TargetHost, sink_tx: mpsc::Sender<TargetHost>) -> Result<()> {
        info!("🐝 SWARM: Iniciando enjambre multi-agente para {}", initial_target.host);
        
        let mut seen_finding_ids = HashSet::new();
        let mut adaptive_context = AdaptiveContext::default();
        let mut correlation_engine = crate::core::CorrelationEngine::new();
        
        let (discovery_tx, mut discovery_rx) = mpsc::channel(100);
        let pipeline = self.pipeline.clone();
        let target = initial_target.clone();
        
        // FASE 1: SCOUT - Discovery inicial
        tokio::spawn(async move {
            let _ = pipeline.run_discovery(&target, discovery_tx).await;
        });

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

            // 2. AGENT EXECUTION
            match role {
                AgentRole::Scout => self.execute_scout(finding, &initial_target, &mut discovery_tx.clone(), &mut adaptive_context, &sink_tx).await?,
                AgentRole::Exploiter => self.execute_exploiter(finding, &initial_target, &mut discovery_tx.clone(), &mut adaptive_context, &sink_tx).await?,
                AgentRole::GhostReporter => self.execute_reporter(finding, &initial_target, &sink_tx).await?,
                AgentRole::Planner => (), // No debería ocurrir como destino
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
        if let Ok(Some((action, tactical))) = self.router.decide_action(&finding, target, &metadata, Some(adaptive_ctx)).await {
            let mut task_target = target.clone();
            task_target.tactical_context = tactical;
            
            let results = self.pipeline.run_specific_plugin(&action, &task_target).await?;
            for nf in results {
                let _ = tx.send(nf).await;
            }
        }
        
        // Reportar hallazgo inicial procesado
        let mut sink_target = target.clone();
        sink_target.findings = vec![finding];
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
                self.budget.add_usage(&analysis.usage);
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
            Err(e) => warn!("⚠️ SWARM [Exploiter]: Error en análisis de explotación: {}", e),
        }

        // Reportar
        let mut sink_target = target.clone();
        sink_target.findings = vec![finding];
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
        sink_target.findings = vec![finding];
        let _ = sink_tx.send(sink_target).await;
        Ok(())
    }
}
