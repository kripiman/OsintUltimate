use anyhow::Result;
use tracing::{info, warn};
use std::time::Duration;
use crate::models::{TargetHost, Finding};
use crate::models::findings::PocDefinition;
use crate::core::c2::C2Operator;
use crate::core::approval_gate::ApprovalStatus::Approved;
use crate::core::validation::PocValidator;

impl PocValidator {
    pub(crate) async fn deploy_c2(&self, target: &TargetHost) -> Result<()> {
        let sliver = crate::plugins::lateral_movement::sliver::SliverScanner::new(self.executor.clone());
        
        match sliver.prepare_payload(target).await {
            Ok(payload_path) => {
                info!("🔱 V14.1 SOVEREIGN: C2 payload staged at {}. Deploying...", payload_path);
                tokio::time::sleep(Duration::from_secs(5)).await;
                
                use crate::core::c2::SessionState;
                if sliver.verify_session(target).await? == SessionState::Sovereign {
                    info!("🎯 V14.1 SOVEREIGN: C2 SESSION ESTABLISHED for {}", target.host);
                } else {
                    let _ = sliver.deploy_payload(target, &payload_path).await;
                }
            }
            Err(e) => warn!("⚠️ V14.1 SOVEREIGN: C2 deployment failed: {}", e),
        }
        Ok(())
    }

    pub(crate) async fn sovereign_handover(&self, finding: &mut Finding, target: &TargetHost, poc: &PocDefinition) -> Result<bool> {
        info!("🏛️ SOVEREIGN MODE: High complexity exploit detected. Initiating HALT.");
        
        let context = format!("### SOVEREIGN HANDOVER ###\nTarget: {}\nFinding: {}\nComplexity: {}", target.host, finding.title, poc.complexity_score);
        let req_id = self.approval_gate.request_approval(&format!("HANDOVER: {}", finding.title), 100, &self.operator, &context).await?;

        if let Some(id) = req_id {
            if self.approval_gate.wait_for_approval(&id, 1200).await {
                if let Some(status) = self.approval_gate.approval_cache().get(&id) {
                    if let Approved { handover_payload: Some(payload), .. } = &*status {
                        info!("🚀 SOVEREIGN: Handover received. Executing...");
                        let output = self.execute_raw_payload(payload, target).await?;
                        let success = output.contains(&poc.expected_pattern) || output.to_lowercase().contains("success");
                        if success { finding.evidence.verified = true; }
                        return Ok(success);
                    }
                }
            }
        }
        Ok(false)
    }
}
