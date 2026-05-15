use crate::models::{Finding, Category, Severity};
use serde::{Deserialize, Serialize};
use anyhow::Result;
use std::sync::Arc;
use tracing::{info, warn, error};
use crate::utils::executor::{StealthExecutor, ExecutorMode};
use rand::rngs::OsRng;
use ed25519_dalek::SigningKey;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PersistenceMethod {
    CredentialInjection,
    PersistentC2,
    ScheduledTask,
    ServiceModification,
    RegistryAutorun,
    SshKeyInjection,
    WebShell,
    ProcessInjection,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TacticalAdvancement {
    pub method: PersistenceMethod,
    pub target_asset: String,
    pub priority: u32,
    pub technical_rationale: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TacticalPlan {
    pub finding_ref: String,
    pub finding_title: String,
    pub severity: Severity,
    pub exploit_vector: String,
    pub affected_nodes: Vec<String>,
    pub proposed_actions: Vec<TacticalAdvancement>,
    pub evidence_path: String,
}

pub struct PersistenceOrchestrator<M: ExecutorMode> {
    pub router: Arc<crate::core::ai::TieredAIRouter>,
    pub c2_manager: Option<Arc<dyn crate::core::orchestrator::c2::C2Operator>>,
    pub executor: Arc<StealthExecutor<M>>,
}

impl<M: ExecutorMode> PersistenceOrchestrator<M> {
    pub fn new(router: Arc<crate::core::ai::TieredAIRouter>, executor: Arc<StealthExecutor<M>>) -> Self {
        Self { router, c2_manager: None, executor }
    }

    pub fn with_c2(mut self, c2: Arc<dyn crate::core::orchestrator::c2::C2Operator>) -> Self {
        self.c2_manager = Some(c2);
        self
    }

    /// Genera un plan táctico de avance basado en un hallazgo verificado.
    pub async fn generate_plan(&self, finding: &Finding) -> Result<TacticalPlan> {
        info!("🎯 [Persistence] Generando plan de avance táctico para: {}", finding.title);
        
        // En una implementación real, esto consultaría a la IA para seleccionar los mejores vectores.
        // Aquí implementamos la lógica base optimizada.
        
        let mut actions = Vec::new();
        
        match finding.category {
            Category::Vulnerability | Category::Misconfiguration => {
                actions.push(TacticalAdvancement {
                    method: PersistenceMethod::PersistentC2,
                    target_asset: finding.id.clone(),
                    priority: 1,
                    technical_rationale: "Established exploit allows for stable C2 channel deployment.".to_string(),
                });
            },
            Category::CredentialLeak => {
                actions.push(TacticalAdvancement {
                    method: PersistenceMethod::CredentialInjection,
                    target_asset: finding.id.clone(),
                    priority: 1,
                    technical_rationale: "Leaked credentials can be injected into secondary services for lateral movement.".to_string(),
                });
            },
            _ => {
                actions.push(TacticalAdvancement {
                    method: PersistenceMethod::SshKeyInjection,
                    target_asset: "AuthorizedKeys".to_string(),
                    priority: 2,
                    technical_rationale: "Standard persistence via public key injection.".to_string(),
                });
            }
        }

        Ok(TacticalPlan {
            finding_ref: finding.id.clone(),
            finding_title: finding.title.clone(),
            severity: finding.severity.clone(),
            exploit_vector: finding.description.clone(),
            affected_nodes: vec![finding.id.clone()],
            proposed_actions: actions,
            evidence_path: format!("evidence/{}", finding.id),
        })
    }

    /// Genera un par de claves Ed25519 efímeras para inyección SSH.
    fn generate_ephemeral_keypair(&self) -> (String, String) {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();
        
        let private_bytes = signing_key.to_bytes();
        let public_bytes = verifying_key.to_bytes();
        
        // Simulación de formato PEM/OpenSSH (simplificado para el scope del V15)
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        let priv_b64 = STANDARD.encode(private_bytes);
        let pub_b64 = STANDARD.encode(public_bytes);
        
        let private_key = format!("-----BEGIN OPENSSH PRIVATE KEY-----\n{}\n-----END OPENSSH PRIVATE KEY-----", priv_b64);
        let public_key = format!("ssh-ed25519 {} osint-ultimate-ephemeral", pub_b64);
        
        (private_key, public_key)
    }


    /// Guarda la clave privada y metadatos operativos en el Vault local.
    async fn archive_vault_data(&self, target: &str, content: &str, extension: &str) {
        let path = format!("workspace/plan/vault_{}.{}", target, extension);
        if let Err(e) = tokio::fs::write(&path, content).await {
            error!("⚠️ [Persistence] Falló archiving vault data: {}", e);
        } else {
            info!("🛡️ [Persistence] Vault data secured in {}", path);
        }
    }

    /// Ejecuta el despliegue de persistencia operativo (DRY-RUN).
    pub async fn consolidate(&self, plan: &TacticalPlan, target: &crate::models::TargetHost) -> Result<()> {
        info!("🚀 [Persistence] [DRY-RUN] Consolidando acceso táctico para: {}", plan.finding_ref);
        
        // Registrar en disco el TacticalPlan
        let plan_json = serde_json::to_string_pretty(plan)?;
        self.archive_vault_data(&plan.finding_ref, &plan_json, "json").await;

        for action in &plan.proposed_actions {
            info!("🛠️ [Persistence] [DRY-RUN] Vector planeado: {:?}", action.method);
            
            match action.method {
                PersistenceMethod::SshKeyInjection => {
                    let (_priv_key, pub_key) = self.generate_ephemeral_keypair();
                    info!("🔑 [Persistence] [DRY-RUN] Se inyectaría la clave: {}", pub_key);
                    info!("💻 [Persistence] [DRY-RUN] Host: {}", target.host);
                },
                PersistenceMethod::WebShell => {
                    info!("🕷️ [Persistence] [DRY-RUN] Se desplegaría un stager PHP ofuscado en {}/var/www/html/.cache.php", target.host);
                },
                _ => {
                    info!("🔱 [Persistence] [DRY-RUN] Se registraría sesión en C2 Manager para {:?}", action.method);
                }
            }
        }
        
        warn!("🛡️ [Persistence] Modo SEGURO: Ninguna acción remota fue ejecutada sobre {}", target.host);
        Ok(())
    }

    /// Verifica que el acceso persistente ha sido consolidado (DRY-RUN).
    pub async fn verify_access(&self, plan: &TacticalPlan, target: &crate::models::TargetHost) -> Result<bool> {
        info!("🔍 [Persistence] [DRY-RUN] Verificando callback de acceso para: {}", plan.finding_ref);
        
        for action in &plan.proposed_actions {
            match action.method {
                PersistenceMethod::SshKeyInjection => {
                    info!("✅ [Persistence] [DRY-RUN] Se verificaría la clave SSH mediante login loopback (whoami) en {}", target.host);
                },
                PersistenceMethod::WebShell => {
                    info!("✅ [Persistence] [DRY-RUN] Se verificaría el WebShell Dropper mediante curl con el header X-Sovereign:");
                    info!("   curl -s -H 'X-Sovereign: ZWNobyAid29ya2luZyI7' http://localhost/.cache.php");
                },
                _ => {
                    info!("✅ [Persistence] [DRY-RUN] Vector asíncrono. Se verificaría el estado en el C2 Manager.");
                }
            }
        }

        Ok(true)
    }
}
