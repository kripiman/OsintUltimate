use crate::models::{Finding, TargetHost, findings::PocStrategy, findings::PocDefinition};
use crate::core::ai_cascade::TieredAIRouter;
use crate::core::approval_gate::{ApprovalGate, User};
use anyhow::{Result, Context};
use std::sync::Arc;
use tracing::{info, warn, error};
use tokio::process::Command;
use std::time::Duration;
use serde_json::json;

pub struct PocValidator {
    router: Arc<TieredAIRouter>,
    approval_gate: Arc<ApprovalGate>,
    operator: User,
}

impl PocValidator {
    pub fn new(router: Arc<TieredAIRouter>, approval_gate: Arc<ApprovalGate>, operator: User) -> Self {
        Self { router, approval_gate, operator }
    }

    /// Intenta validar un hallazgo ejecutando un PoC generado por IA.
    pub async fn validate(&self, finding: &mut Finding, target: &TargetHost) -> Result<bool> {
        // 1. Obtener o generar la definición del PoC
        let poc = if let Some(ref analysis) = finding.ai_analysis {
            if let Some(ref poc) = analysis.poc {
                poc.clone()
            } else {
                self.generate_poc(finding, target).await?
            }
        } else {
            return Ok(false);
        };

        // Actualizar el hallazgo si la IA generó uno nuevo
        if let Some(ref mut analysis) = finding.ai_analysis {
            if analysis.poc.is_none() {
                analysis.poc = Some(poc.clone());
            }
        }

        info!("🧪 SENTINEL: Iniciando validación de PoC para '{}' (Estrategia: {:?})", finding.title, poc.strategy);

        // 2. Gestionar aprobaciones para PoCs intrusivos
        if poc.is_intrusive {
            let action_desc = format!("PoC EXPLOIT: {} on {}", finding.title, target.host);
            let req_id = self.approval_gate.request_approval(
                &action_desc,
                95, // Riesgo crítico para exploits
                &self.operator,
                &format!("Sentinel propone ejecutar el siguiente PoC intrusivo:\n\nStrategy: {:?}\nPayload: {}\nExpected: {}", poc.strategy, poc.payload, poc.expected_pattern)
            ).await?;

            if let Some(id) = req_id {
                info!("⏳ SENTINEL: PoC intrusivo '{}' requiere aprobación manual en el Dashboard (ID: {})", finding.title, id);
                if !self.approval_gate.wait_for_approval(&id, 600).await { // 10 min timeout
                    warn!("🚫 SENTINEL: Validación de PoC abortada: No se recibió aprobación.");
                    return Ok(false);
                }
                info!("✅ SENTINEL: PoC aprobado. Procediendo con la ejecución...");
            }
        }

        // 3. Ejecución segura según la estrategia
        let execution_result = match poc.strategy {
            PocStrategy::ShellCommand => self.execute_shell(&poc.payload).await,
            PocStrategy::HttpPayload => self.execute_http(&poc.payload, target).await,
            PocStrategy::NucleiTemplate => Ok("Estrategia Nuclei requiere integración con el plugin. Marcado como pendiente.".to_string()),
        };

        // 4. Verificación de resultados
        match execution_result {
            Ok(output) => {
                let success = output.contains(&poc.expected_pattern);
                if success {
                    info!("🎯 SENTINEL: ¡PoC EXITOSO! Hallazgo verificado: {}", finding.title);
                    finding.evidence.verified = true;
                } else {
                    warn!("❌ SENTINEL: PoC fallido. El patrón esperado '{}' no se encontró en la salida.", poc.expected_pattern);
                }
                Ok(success)
            }
            Err(e) => {
                error!("⚠️ SENTINEL: Error durante la ejecución del PoC: {}", e);
                Ok(false)
            }
        }
    }

    async fn generate_poc(&self, finding: &Finding, target: &TargetHost) -> Result<PocDefinition> {
        info!("🧠 SENTINEL: Solicitando a la IA Premium que genere un PoC para {}", finding.title);
        
        let prompt = format!(
            "Genera un Proof of Concept (PoC) técnico y SEGURO para validar el siguiente hallazgo:\n\
             Hallazgo: {}\n\
             Descripción: {}\n\
             Evidencia original: {:?}\n\
             Objetivo: {}\n\n\
             Responde ÚNICAMENTE con un JSON válido que siga este esquema:\n\
             {{\n  \"strategy\": \"shell_command\" | \"http_payload\",\n  \"payload\": \"comando o sub-ruta\",\n  \"expected_pattern\": \"cadena que confirma el éxito\",\n  \"is_intrusive\": true | false\n}}",
            finding.title, finding.description, finding.evidence.data, target.host
        );

        // Forzar nivel Premium para generación de exploits
        let analysis = self.router.analyze_with_level(finding, target, crate::core::ai_cascade::RouteLevel::Premium).await?;
        
        // Aquí asumimos que la IA puede devolver el PoC dentro de la respuesta o tenemos un método nuevo.
        // Como acabamos de añadir el campo `poc` a `AIAnalysis`, el `TieredAIRouter` debería estar actualizado.
        // Si no, podemos parsear la respuesta aquí.
        
        if let Some(poc) = analysis.poc {
            Ok(poc)
        } else {
            // Fallback: Si la IA no lo puso en el campo específico, intentar extraerlo del summary si es JSON
            let text = analysis.summary; 
            let poc_json: PocDefinition = serde_json::from_str(extract_json(&text))
                .context("No se pudo generar una definición de PoC válida desde la IA")?;
            Ok(poc_json)
        }
    }

    async fn execute_shell(&self, command: &str) -> Result<String> {
        // Validación estricta anti-Shell Injection
        let dangerous_chars = ['&', '|', ';', '$', '`', '>', '<'];
        if command.chars().any(|c| dangerous_chars.contains(&c)) {
            anyhow::bail!("Security Violation: PoC command contains forbidden shell operators.");
        }

        let parts: Vec<&str> = command.split_whitespace().collect();
        if parts.is_empty() {
            anyhow::bail!("Security Violation: Empty command.");
        }

        // Whitelist comandos permitidos para PoC (Removidos: python3, nc por riesgo ejecución arbitraria)
        let allowed_binaries = ["curl", "nmap", "ping", "whoami", "id"];
        if !allowed_binaries.contains(&parts[0]) {
            anyhow::bail!("Security Violation: Binary '{}' is not in the whitelist of safe PoC commands.", parts[0]);
        }

        let mut cmd = Command::new(parts[0]);
        if parts.len() > 1 {
            cmd.args(&parts[1..]);
        }
        
        let res = tokio::time::timeout(Duration::from_secs(10), cmd.output()).await;
        let output = res.context("PoC command timed out")??;
        
        let combined = format!(
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(combined)
    }

    async fn execute_http(&self, payload: &str, target: &TargetHost) -> Result<String> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .danger_accept_invalid_certs(true)
            .build()?;
        
        let url = if payload.starts_with("http") {
            payload.to_string()
        } else {
            format!("http://{}{}{}", target.host, if payload.starts_with('/') { "" } else { "/" }, payload)
        };

        if let Ok(parsed_url) = url::Url::parse(&url) {
            if let Some(host) = parsed_url.host_str() {
                if !crate::utils::liveness::is_ssrf_safe_host(host) {
                    anyhow::bail!("Security Violation: HTTP PoC payload attempts to reach forbidden internal/metadata host: {}", host);
                }
            }
        }

        let res = client.get(&url).send().await?;
        let status = res.status();
        let body = res.text().await?;
        
        Ok(format!("Status: {}\nBody: {}", status, body))
    }
}

fn extract_json(text: &str) -> &str {
    if let Some(start) = text.find('{') {
        if let Some(end) = text.rfind('}') { return &text[start..=end]; }
    }
    text
}
