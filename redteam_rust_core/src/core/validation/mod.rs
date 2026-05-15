use crate::models::{TargetHost, Finding, ValidationStatus};
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
#[cfg(feature = "sovereign")]
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
        let poc = if let Some(ref analysis) = finding.enrichment.ai_analysis {
            if let Some(ref poc) = analysis.poc {
                poc.clone()
            } else {
                self.generate_poc(finding, target, attack_context).await?
            }
        } else {
            return Ok(false);
        };

        if let Some(ref mut analysis) = finding.enrichment.ai_analysis {
            if analysis.poc.is_none() {
                analysis.poc = Some(poc.clone());
            }
        }

        info!("🧪 SENTINEL: Iniciando validación de PoC para '{}' (Estrategia: {:?})", finding.core.title, poc.strategy);

        // V14.1: Sovereign Mode Bifurcation
        #[cfg(feature = "sovereign")]
        {
            if poc.complexity_score >= 70 {
                return self.sovereign_handover(finding, target, &poc).await;
            }
        }
        #[cfg(not(feature = "sovereign"))]
        {
            if poc.complexity_score >= 70 {
                warn!("🚫 SENTINEL: PoC con complejidad {} requiere sovereign mode. Skipping en modo Bug Bounty.", poc.complexity_score);
                return Ok(false);
            }
        }

        // 2. Gestionar aprobaciones para PoCs intrusivos
        if poc.is_intrusive {
            let action_desc = format!("PoC EXPLOIT: {} on {}", finding.core.title, target.host);
            
            // Human Pivot: Generate a readable explanation for the approval request
            let human_context = format!(
                "Sentinel propone ejecutar el siguiente PoC intrusivo:\n\nStrategy: {:?}\nPayload: {}\nExpected: {}\n\n¿Desea autorizar esta acción?",
                poc.strategy, poc.payload, poc.expected_pattern
            );

            let req_id = self.approval_gate.request_approval(
                &action_desc,
                95, 
                &self.operator,
                &human_context
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

        // 4. Verificación de resultados y Pipeline de Anti-Alucinación (V15)
        let mut success = match execution_result {
            Ok(output) => {
                let s = output.contains(&poc.expected_pattern);
                if s {
                    info!("🎯 SENTINEL: ¡PoC EXITOSO! Hallazgo verificado: {}", finding.core.title);
                    if let Some(ref mut ev) = finding.evidence.primary {
                        ev.verified = true;
                    }
                    #[cfg(feature = "sovereign")]
                    {
                        if finding.core.severity >= crate::models::Severity::High {
                            let _ = self.deploy_c2(target).await;
                        }
                    }
                } else {
                    warn!("❌ SENTINEL: PoC fallido. El patrón esperado '{}' no se encontró o no se detectaron severidades críticas/altas.", poc.expected_pattern);
                }
                s
            }
            Err(e) => {
                error!("⚠️ SENTINEL: Error durante la ejecución del PoC: {}", e);
                false
            }
        };

        // V15: Ejecutar el Pipeline Anti-Alucinación para refinamiento final
        if let Some(ref pm) = self.proxy_manager {
            let _ = crate::core::verification::ValidationPipeline::validate(finding, target, pm.clone(), self.router.clone()).await;
            
            // V15.4: Active OOB Trigger
            if finding.core.severity >= crate::models::Severity::High && finding.validation.as_ref().map(|v| v.status).unwrap_or(ValidationStatus::Unverified) != ValidationStatus::Verified
                 && (finding.core.title.to_lowercase().contains("ssrf") || finding.core.title.to_lowercase().contains("blind")) {
                     info!("🧬 SENTINEL [V15.4]: Active OOB requested. Triggering proactive re-run...");
                 }

            // Actualizar el éxito basado en el veredicto del Pipeline
            if let Some(ref val) = finding.validation {
                if val.status == ValidationStatus::PseudoFalse {
                    info!("🛑 SENTINEL: Pipeline marcó hallazgo como PseudoFalse. Sobrescribiendo éxito.");
                    success = false;
                    if let Some(ref mut ev) = finding.evidence.primary {
                        ev.verified = false;
                    }
                }
            }
        }

        Ok(success)
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
            Ok(stdout)
        } else {
            anyhow::bail!("Nuclei execution completed but no [critical] or [high] vulnerabilities were found.");
        }
    }
}
