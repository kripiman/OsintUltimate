use crate::models::{Finding, TargetHost, findings::PocStrategy, findings::PocDefinition};
use crate::core::ai_cascade::TieredAIRouter;
use crate::core::approval_gate::{ApprovalGate, User};
use anyhow::{Result, Context};
use std::sync::Arc;
use tracing::{info, warn, error};
use tokio::process::Command;
use std::time::Duration;
use serde_json::json;
use std::path::Path;

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
            PocStrategy::SafeCommand => self.execute_safe_command(&poc.payload, target).await,
            PocStrategy::HttpPayload => self.execute_http(&poc.payload, target).await,
            PocStrategy::TcpCheck => self.execute_tcp_check(&poc.payload, target).await,
            PocStrategy::IcmpPing => self.execute_icmp_ping(target).await,
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
             {{\n  \
               \"strategy\": \"safe_command\" | \"http_payload\" | \"tcp_check\" | \"icmp_ping\",\n  \
               \"payload\": \"JSON array para safe_command (p.ej. [\\\"nmap\\\", \\\"-p80\\\", \\\"-sV\\\"]) o sub-ruta para http_payload\",\n  \
               \"expected_pattern\": \"cadena que confirma el éxito\",\n  \
               \"is_intrusive\": true | false\n\
             }}",
            finding.title, finding.description, finding.evidence.data, target.host
        );

        // Forzar nivel Premium para generación de exploits
        let analysis = self.router.analyze_with_level(finding, target, crate::core::ai_cascade::RouteLevel::Premium).await?;
        
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

    /// V12 HARDENING (CRIT-001): Template-based execution (P0) to prevent Argument Injection.
    async fn execute_safe_command(&self, payload: &str, target: &TargetHost) -> Result<String> {
        let params: serde_json::Value = serde_json::from_str(payload)
            .context("Invalid JSON payload for safe_command. Expected a JSON object with template parameters.")?;
        
        // V12 HARDENING (HIGH-001): Mandatory IP Pinning.
        // Use resolved_ip if available, fallback to ip, or bail.
        let target_ip = target.resolved_ip.as_ref()
            .or(target.ip.as_ref())
            .context("V12: Target IP must be resolved before PoC execution (Enterprise Security Requirement)")?;

        // Ensure the IP is safe via central utility
        let ip_addr = target_ip.parse::<std::net::IpAddr>().context("Invalid IP in TargetHost")?;
        if !crate::utils::liveness::is_ssrf_safe_host(target_ip).await {
             anyhow::bail!("V12 SSRF Blocked: Target IP {} is in a restricted range.", target_ip);
        }

        let binary = params["binary"].as_str().context("Missing 'binary' field in payload")?;

        // V12 HARDENING (CRIT-001): Reconstruct command from a strict, immutable template.
        // We do NOT allow the AI to provide any flags/arguments directly, only values for templates.
        let safe_args = match binary {
            "nmap" => {
                let port = params["port"].as_u64().unwrap_or(80);
                if port == 0 || port > 65535 { anyhow::bail!("Invalid port: {}", port); }
                
                // Fixed, safe template for nmap
                vec!["-p".to_string(), port.to_string(), "-sV".to_string(), "--version-light".to_string(), "-Pn".to_string(), target_ip.clone()]
            },
            "curl" => {
                let path = params["path"].as_str().unwrap_or("/");
                // Sanitize path: no spaces, no .., must start with /
                if path.contains(' ') || path.contains("..") || !path.starts_with('/') {
                    anyhow::bail!("V12 Policy Violation: Illegal characters or format in curl path.");
                }

                // Force IP, disable redirects, and use a strict timeout.
                vec!["-I".to_string(), "--fail".to_string(), "--max-time".to_string(), "10".to_string(), format!("http://{}{}", target_ip, path)]
            },
            "ping" => vec!["-c".to_string(), "3".to_string(), "-W".to_string(), "5".to_string(), target_ip.clone()],
            "dig" => vec!["+short".to_string(), target_ip.clone()],
            "whois" => vec![target_ip.clone()],
            "host" => vec![target_ip.clone()],
            _ => anyhow::bail!("V12 Policy Violation: Binary '{}' is not supported in Strict Template mode.", binary),
        };

        let mut cmd = crate::utils::common::stealth_command(binary);
        cmd.args(&safe_args);

        let res = tokio::time::timeout(Duration::from_secs(15), cmd.output()).await;
        let output = res.context("PoC command timed out")??;
        
        let combined = format!(
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(combined)
    }

    async fn execute_tcp_check(&self, payload: &str, target: &TargetHost) -> Result<String> {
        let port = payload.parse::<u16>().context("Invalid port for tcp_check")?;
        // V12: Force IP for TCP checks (Priority resolved_ip)
        let target_addr = target.resolved_ip.as_ref()
            .or(target.ip.as_ref())
            .context("V12: Target IP must be resolved before TCP check execution")?;
        let _ip_addr = target_addr.parse::<std::net::IpAddr>().context("Invalid IP in target for TCP check")?;
        let addr = format!("{}:{}", target_addr, port);
        
        // SSRF Check for TCP stream
        if !crate::utils::liveness::is_ssrf_safe_host(target_addr).await {
            anyhow::bail!("V12 SSRF Blocked: TCP check to restricted IP range.");
        }

        match tokio::time::timeout(Duration::from_secs(5), tokio::net::TcpStream::connect(&addr)).await {
            Ok(Ok(_)) => Ok(format!("TCP Port {} is OPEN on {}", port, target_addr)),
            Ok(Err(e)) => Ok(format!("TCP Port {} is CLOSED Or Filtered on {}: {}", port, target_addr, e)),
            Err(_) => Ok(format!("TCP Port {} connection to {} TIMED OUT", port, target_addr)),
        }
    }

    async fn execute_icmp_ping(&self, target: &TargetHost) -> Result<String> {
        let mut cmd = crate::utils::common::stealth_command("ping");
        // V12: Force IP for ICMP (Priority resolved_ip)
        let target_addr = target.resolved_ip.as_ref()
            .or(target.ip.as_ref())
            .context("V12: Target IP must be resolved before ICMP ping execution")?;
        let _ip_addr = target_addr.parse::<std::net::IpAddr>().context("Invalid IP in target for ICMP ping")?;
        
        if !crate::utils::liveness::is_ssrf_safe_host(target_addr).await {
            anyhow::bail!("V12 SSRF Blocked: Ping to restricted IP range.");
        }

        cmd.arg("-c").arg("3").arg(target_addr);
        
        let res = tokio::time::timeout(Duration::from_secs(10), cmd.output()).await;
        let output = res.context("Ping PoC timed out")??;
        
        if output.status.success() {
            Ok(format!("Ping to {} successful", target_addr))
        } else {
            Ok(format!("Ping to {} failed", target_addr))
        }
    }

    async fn execute_http(&self, payload: &str, target: &TargetHost) -> Result<String> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .danger_accept_invalid_certs(true)
            .build()?;
        
        // V12 HARDENING (HIGH-001): Mandatory IP Pinning & SSRF validation (Priority resolved_ip)
        let target_ip = target.resolved_ip.as_ref()
            .or(target.ip.as_ref())
            .context("V12: Target IP must be resolved before HTTP PoC execution")?;
        
        // Ensure the IP is safe via central utility
        if !crate::utils::liveness::is_ssrf_safe_host(target_ip).await {
             anyhow::bail!("V12 SSRF Blocked: Target IP {} is in a restricted range.", target_ip);
        }

        let path = if payload.starts_with("http") {
             // Extract path if AI provided a full URL, but force our pinned IP.
             reqwest::Url::parse(payload).map(|u| u.path().to_string()).unwrap_or_else(|_| "/".to_string())
        } else {
             payload.to_string()
        };

        let safe_path = if path.starts_with('/') { path } else { format!("/{}", path) };
        let url = format!("http://{}{}", target_ip, safe_path);

        info!("🌐 V12 HTTP PoC (Pinned): Requesting {}", url);
        let mut request = client.get(&url);
        
        // Set Host header to the original hostname to support vhosts on pinned IP.
        request = request.header("Host", &target.host);

        let res = request.send().await?;
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
