use crate::core::validation::PocValidator;
use anyhow::Result;
use tracing::{info, warn};
use std::time::Duration;
use crate::models::{TargetHost, Finding};
use crate::models::findings::PocDefinition;
use crate::core::orchestrator::c2::C2Operator;
use crate::core::approval_gate::ApprovalStatus::Approved;
use crate::utils::executor::ExecutorMode;

impl<M: ExecutorMode> PocValidator<M> {
    pub(crate) async fn deploy_c2(&self, target: &TargetHost) -> Result<()> {
        let sovereign_operator = crate::plugins::lateral_movement::sliver_sovereign::SovereignSliverOperator::<M>::new(self.executor.clone()).await?;
        
        match sovereign_operator.prepare_payload(target).await {
            Ok(payload_path) => {
                info!("🔱 V14.1 SOVEREIGN: Autonomous C2 payload staged at {}. Deploying...", payload_path);
                
                use crate::core::orchestrator::c2::SessionState;
                match sovereign_operator.verify_session(target).await? {
                    SessionState::Sovereign => {
                        info!("🎯 V14.1 SOVEREIGN: C2 SESSION ALREADY ESTABLISHED for {}", target.host);
                    }
                    _ => {
                        sovereign_operator.deploy_payload(target, &payload_path).await?;
                        tokio::time::sleep(Duration::from_secs(10)).await;
                        
                        if sovereign_operator.verify_session(target).await? == SessionState::Sovereign {
                            info!("🎯 V14.1 SOVEREIGN: AUTONOMOUS C2 SESSION ESTABLISHED for {}", target.host);
                        }
                    }
                }
            }
            Err(e) => warn!("⚠️ V14.1 SOVEREIGN: Autonomous C2 deployment failed: {}", e),
        }
        Ok(())
    }

    pub(crate) async fn sovereign_handover(&self, finding: &mut Finding, target: &TargetHost, poc: &PocDefinition) -> Result<bool> {
        info!("🏛️ SOVEREIGN MODE: High complexity exploit detected. Initiating HALT for mission briefing.");
        
        let raw_instruction = format!("Generate a professional mission briefing for a human operator to manually validate this: {}. Target: {}. Strategy: {:?}", finding.core.title, target.host, poc.strategy);
        let human_instruction = crate::core::ai::caveman::CavemanOptimizer::pivot_to_human_readable(&raw_instruction, true);
        
        let analysis = self.router.analyze_with_level(finding, target, Some(&human_instruction), crate::core::ai::RouteLevel::Premium, crate::core::ai::CavemanLevel::Off).await?;
        
        let context = format!(
            "### 🏛️ SOVEREIGN MISSION BRIEFING (MANUAL EXPLOIT) ###\n\n\
            Target: {}\n\
            Finding: {}\n\
            Complexity: {}\n\n\
            --- MISSION CONTEXT ---\n\
            {}\n\n\
            --- EXPLOIT PATH ---\n\
            {}", 
            target.host, finding.core.title, poc.complexity_score, analysis.summary, analysis.exploit_path
        );

        let req_id = self.approval_gate.request_approval(&format!("HANDOVER: {}", finding.core.title), 100, &self.operator, &context).await?;

        if let Some(id) = req_id {
            if self.approval_gate.wait_for_approval(&id, 1200).await {
                if let Some(status) = self.approval_gate.approval_cache().get(&id) {
                    if let Approved { handover_payload: Some(payload), .. } = &*status {
                        info!("🚀 SOVEREIGN: Handover received. Executing...");
                        let output = self.execute_raw_payload(payload, target).await?;
                        let success = output.contains(&poc.expected_pattern) || output.to_lowercase().contains("success");
                        if success {
                            if let Some(ref mut ev) = finding.evidence.primary {
                                ev.verified = true;
                            }
                        }
                        return Ok(success);
                    }
                }
            }
        }
        Ok(false)
    }
}
