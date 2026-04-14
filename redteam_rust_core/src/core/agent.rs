use crate::models::TargetHost;
use crate::core::pipeline::Pipeline;
use crate::core::ai::AdaptiveContext;
use anyhow::Result;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::info;

pub struct AutonomousAgent {
    router: Arc<crate::core::ai::TieredAIRouter>,
    pipeline: Arc<Pipeline>,
    approval_gate: Arc<crate::core::approval_gate::ApprovalGate>,
    operator: crate::core::approval_gate::User,
    poc_validator: Arc<crate::core::PocValidator>,
}

impl AutonomousAgent {
    pub fn new(
        router: Arc<crate::core::ai::TieredAIRouter>, 
        pipeline: Arc<Pipeline>, 
        approval_gate: Arc<crate::core::approval_gate::ApprovalGate>,
        proxy_manager: Option<Arc<crate::utils::proxy::ProxyManager>>,
        executor: Arc<crate::utils::executor::StealthExecutor>,
        policy: Arc<dyn crate::core::policy::PolicyProvider>,
    ) -> Self {
        let operator = crate::core::approval_gate::User {
            id: "sentinel-agent".to_string(),
            name: "Sentinel-AI".to_string(),
            role: crate::core::approval_gate::UserRole::RedTeamFull,
            authorized_at: chrono::Utc::now(),
        };
        let poc_validator = Arc::new(crate::core::PocValidator::new(
            router.clone(),
            approval_gate.clone(),
            operator.clone(),
            executor.clone(),
            policy.clone(),
            proxy_manager.clone(),
        ));
        Self { router, pipeline, approval_gate, operator, poc_validator }
    }

    pub async fn run_autopilot(&self, initial_target: TargetHost, sink_tx: mpsc::Sender<TargetHost>) -> Result<()> {
        info!("🤖 SENTINEL: Iniciando ciclo autónomo adaptativo para {}", initial_target.host);
        let mut seen_finding_ids = std::collections::HashSet::new();
        let mut adaptive_context = AdaptiveContext::default();
        let mut correlation_engine = crate::core::CorrelationEngine::new();
        let (tx, mut rx) = mpsc::channel(100);
        let pipeline = Arc::clone(&self.pipeline);
        let target = initial_target.clone();
        let tx_discovery = tx.clone();
        tokio::spawn(async move { let _ = pipeline.run_discovery(&target, tx_discovery).await; });

        while let Some(finding) = rx.recv().await {
            if seen_finding_ids.contains(&finding.id) { continue; }
            seen_finding_ids.insert(finding.id.clone());
            
            correlation_engine.add_finding(finding.clone());
            let attack_context = correlation_engine.get_context_summary(&finding.id);
            
            let analysis = self.router.analyze(&finding, &initial_target, attack_context.as_deref()).await?;
            let mut final_finding = finding.with_ai_analysis(analysis.clone()).with_remediation(&analysis.remediation);
            if let Some(tags) = analysis.mitre_attack { final_finding = final_finding.with_mitre_attack(tags); }
            
            if analysis.risk_score >= 8 || final_finding.severity == crate::models::Severity::High || final_finding.severity == crate::models::Severity::Critical {
                info!("🧪 SENTINEL: Detectado hallazgo crítico/alto. Iniciando pipeline de validación de PoC...");
                let _ = self.poc_validator.validate(&mut final_finding, &initial_target, attack_context.as_deref()).await;
            }

            let mut sink_target = initial_target.clone();
            sink_target.findings = Arc::new(vec![final_finding.clone()]);
            let paths = correlation_engine.get_attack_paths();
            if !paths.is_empty() {
                 Arc::make_mut(&mut sink_target.extra_data)["attack_paths"] = serde_json::json!(paths);
            }
            let _ = sink_tx.send(sink_target).await;

            let metadata = self.pipeline.get_plugin_metadata();
            let attack_context = correlation_engine.get_context_summary(&final_finding.id);
            if let Ok(Some((action, tactical))) = self.router.decide_action(&final_finding, &initial_target, &metadata, attack_context.as_deref(), Some(&adaptive_context)).await {
                if self.request_operator_approval(&action).await {
                    let mut task_target = initial_target.clone();
                    task_target.tactical_context = Arc::new(tactical.clone());
                    adaptive_context.previous_actions.push(action.clone());
                    let results = self.pipeline.run_specific_plugin(&action, &task_target).await?;
                    if results.is_empty() {
                         adaptive_context.block_count += 1;
                         adaptive_context.was_detected = true;
                    } else {
                         adaptive_context.was_detected = false;
                         for nf in results { let _ = tx.send(nf).await; }
                    }
                }
            }
            if adaptive_context.previous_actions.len() > 50 { break; }
        }
        Ok(())
    }

    async fn request_operator_approval(&self, action: &str) -> bool {
        if self.approval_gate.is_approved(action).await { return true; }
        match self.approval_gate.request_approval(action, 85, &self.operator, "Autonomous Adaptive Loop").await {
            Ok(None) => true,
            _ => false,
        }
    }
}
