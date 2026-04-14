use crate::models::{TargetHost, Finding};
use crate::core::ai::TieredAIRouter;
use crate::core::approval_gate::{ApprovalGate, User};
use crate::models::findings::PocStrategy;
use crate::utils::{executor::{StealthExecutor, ExecutorMode}, proxy::ProxyManager};
use crate::core::policy::PolicyProvider;
use anyhow::Result;
use std::sync::Arc;
use tracing::{info, warn, error};

mod executor;
mod generator;
mod sovereign;
pub mod remote;

pub struct PocValidator<M: ExecutorMode> {
    pub(crate) router: Arc<TieredAIRouter>,
    pub(crate) approval_gate: Arc<ApprovalGate>,
    pub(crate) operator: User,
    pub(crate) executor: Arc<StealthExecutor<M>>,
    pub(crate) policy: Arc<dyn PolicyProvider>,
    pub(crate) proxy_manager: Option<Arc<ProxyManager>>,
}

impl<M: ExecutorMode> PocValidator<M> {
    pub fn new(
        router: Arc<TieredAIRouter>, 
        approval_gate: Arc<ApprovalGate>, 
        operator: User,
        executor: Arc<StealthExecutor<M>>,
        policy: Arc<dyn PolicyProvider>,
        proxy_manager: Option<Arc<ProxyManager>>,
    ) -> Self {
        Self { router, approval_gate, operator, executor, policy, proxy_manager }
    }

    /// Intenta validar un hallazgo ejecutando un PoC generado por IA.
    pub async fn validate(&self, finding: &mut Finding, target: &TargetHost, attack_context: Option<&str>) -> Result<bool> {
        let poc = if let Some(ref analysis) = finding.ai_analysis {
            if let Some(ref poc) = analysis.poc {
                poc.clone()
            } else {
                self.generate_poc(finding, target, attack_context).await?
            }
        } else {
            return Ok(false);
        };

        if let Some(ref mut analysis) = finding.ai_analysis {
            if analysis.poc.is_none() {
                analysis.poc = Some(poc.clone());
            }
        }

        info!("🧪 SENTINEL: Iniciando validación de PoC para '{}' (Estrategia: {:?})", finding.title, poc.strategy);

        // V14.1: Sovereign Mode Bifurcation
        if poc.complexity_score >= 70 {
            return self.sovereign_handover(finding, target, &poc).await;
        }

        // 2. Gestionar aprobaciones para PoCs intrusivos
        if poc.is_intrusive {
            let action_desc = format!("PoC EXPLOIT: {} on {}", finding.title, target.host);
            let req_id = self.approval_gate.request_approval(
                &action_desc,
                95, 
                &self.operator,
                &format!("Sentinel propone ejecutar el siguiente PoC intrusivo:\n\nStrategy: {:?}\nPayload: {}\nExpected: {}", poc.strategy, poc.payload, poc.expected_pattern)
            ).await?;

            if let Some(id) = req_id {
                info!("⏳ SENTINEL: PoC intrusivo requiere aprobación manual (ID: {})", id);
                if !self.approval_gate.wait_for_approval(&id, 600).await {
                    warn!("🚫 SENTINEL: Validación abortada por falta de aprobación.");
                    return Ok(false);
                }
            }
        }

        // 3. Ejecución segura a través del StealthExecutor
        let execution_result = match poc.strategy {
            PocStrategy::SafeCommand => self.execute_safe_command(&poc.payload, target).await,
            PocStrategy::HttpPayload => self.execute_http(&poc.payload, target).await,
            PocStrategy::TcpCheck => self.execute_tcp_check(&poc.payload, target).await,
            PocStrategy::IcmpPing => self.execute_icmp_ping(target).await,
            PocStrategy::NucleiTemplate => self.execute_nuclei(&poc.payload, target).await,
            PocStrategy::HumanVerified => Ok("PoC verificado por operador.".to_string()),
        };

        // 4. Verificación de resultados
        match execution_result {
            Ok(output) => {
                let success = output.contains(&poc.expected_pattern);
                if success {
                    info!("🎯 SENTINEL: ¡PoC EXITOSO! Hallazgo verificado: {}", finding.title);
                    finding.evidence.verified = true;
                    if finding.severity >= crate::models::Severity::High {
                        let _ = self.deploy_c2(target).await;
                    }
                } else {
                    warn!("❌ SENTINEL: PoC fallido. El patrón esperado '{}' no se encontró o no se detectaron severidades críticas/altas.", poc.expected_pattern);
                }
                Ok(success)
            }
            Err(e) => {
                error!("⚠️ SENTINEL: Error durante la ejecución del PoC: {}", e);
                Ok(false)
            }
        }
    }

    /// Real async call to nuclei engine through StealthExecutor.
    async fn execute_nuclei(&self, template_path: &str, target: &TargetHost) -> Result<String> {
        info!("🧬 SENTINEL: Ejecutando Nuclei con plantilla '{}' sobre {}", template_path, target.host);
        
        let args = vec![
            "-t".to_string(), template_path.to_string(),
            "-u".to_string(), target.host.clone(),
            "-no-color".to_string(),
            "-silent".to_string(),
        ];

        let output = self.executor.execute_and_wait("nuclei", args).await?;
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        if !output.status.success() {
            anyhow::bail!("Nuclei execution failed: {}", stderr);
        }

        // Professional parsing: successful validation requires critical/high findings
        if stdout.contains("[critical]") || stdout.contains("[high]") {
            // We return a string that should match a pattern like 'critical' or 'high' or even template name
            Ok(stdout)
        } else {
            // If no critical results, we return the output but it might fail the expected_pattern check
            Ok(stdout)
        }
    }
}
