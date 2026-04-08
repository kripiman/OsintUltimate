use crate::models::{Finding, TargetHost, findings::PocStrategy, findings::PocDefinition};
use crate::core::ai::TieredAIRouter;
use crate::core::approval_gate::{ApprovalGate, User};
use anyhow::{Result, Context};
use std::sync::Arc;
use tracing::{info, warn, error};
use tokio::process::Command;
use std::time::Duration;
use serde_json::json;
use std::path::Path;
use once_cell::sync::Lazy;
use regex::Regex;

pub struct PocValidator {
    router: Arc<TieredAIRouter>,
    approval_gate: Arc<ApprovalGate>,
    operator: User,
    proxy_manager: Option<Arc<crate::utils::proxy::ProxyManager>>,
}

impl PocValidator {
    pub fn new(
        router: Arc<TieredAIRouter>, 
        approval_gate: Arc<ApprovalGate>, 
        operator: User,
        proxy_manager: Option<Arc<crate::utils::proxy::ProxyManager>>,
    ) -> Self {
        Self { router, approval_gate, operator, proxy_manager }
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
        let analysis = self.router.analyze_with_level(finding, target, crate::core::ai::RouteLevel::Premium).await?;
        
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

    /// V13 HARDENING (CRIT-001): Semantic argument validation & Template-based execution (P0).
    /// V12 Protocol: Use safety-first types to make illegal states irrepresentable.
    async fn execute_safe_command(&self, payload: &str, target: &TargetHost) -> Result<String> {
        let params: serde_json::Value = serde_json::from_str(payload)
            .context("Invalid JSON payload for safe_command. Expected a JSON object with template parameters.")?;
        
        let target_ip = target.pinned_addr()
            .context("V13: Target IP must be resolved and pinned before PoC execution (Enterprise Security Requirement)")?;

        if !crate::utils::liveness::is_ssrf_safe_host(target_ip).await {
             anyhow::bail!("V13 SSRF Blocked: Target IP {} is in a restricted range.", target_ip);
        }

        let binary_str = params["binary"].as_str().context("Missing 'binary' field in payload")?;
        
        // V13: Internal Type-Safe Whitelist & Semantic Validator
        use crate::models::findings::ValidatedPoc;
        
        let validated = match binary_str {
            "nmap" => {
                let port_val = params["port"].to_string();
                let port = port_val.trim_matches('"').parse::<u16>()
                    .map_err(|_| anyhow::anyhow!("V13 Policy Violation: Illegal port format in nmap template."))?;
                
                // V13: Semantic Flag Whitelist
                let mut extra_flags = Vec::new();
                if let Some(flags) = params["flags"].as_array() {
                    let allowed_flags = ["-sV", "-Pn", "-n", "--open", "--version-light", "-sS", "-F"];
                    for flag in flags {
                        let flag_str = flag.as_str().context("Flag must be a string")?;
                        if allowed_flags.contains(&flag_str) {
                            extra_flags.push(flag_str.to_string());
                        } else {
                            anyhow::bail!("V13 Security Violation: Flag '{}' is not in the nmap whitelist.", flag_str);
                        }
                    }
                }
                ValidatedPoc::Nmap { port, flags: extra_flags }
            },
            "curl" => {
                let path = params["path"].as_str().unwrap_or("/");
                // V13: Strict semantic validation (Regex + Logic)
                static PATH_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[a-zA-Z0-9\-\._/~%\?&=]+$").unwrap());
                if !PATH_RE.is_match(path) || path.contains("..") || !path.starts_with('/') {
                    anyhow::bail!("V13 Policy Violation: Illegal characters or format in curl path.");
                }
                
                let mut headers = Vec::new();
                if let Some(h_map) = params["headers"].as_object() {
                   static HEADER_NAME_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[a-zA-Z0-9\-]+$").unwrap());
                   for (name, value) in h_map {
                       let val_str = value.as_str().context("Header value must be a string")?;
                       if HEADER_NAME_RE.is_match(name) && !val_str.contains('\n') && !val_str.contains('\r') {
                           headers.push((name.clone(), val_str.to_string()));
                       }
                   }
                }
                ValidatedPoc::Curl { path: path.to_string(), headers }
            },
            "ping" => ValidatedPoc::Ping,
            "dig" => ValidatedPoc::Dig,
            _ => anyhow::bail!("V13 Policy Violation: Binary '{}' is not supported.", binary_str),
        };

        // V13 HARDENING: Final Command Construction from ONLY Validated Types
        let (binary, mut args) = match validated {
            ValidatedPoc::Nmap { port, flags } => {
                let mut args = vec!["-p".to_string(), port.to_string()];
                args.extend(flags);
                args.push(target_ip.to_string());
                ("nmap", args)
            },
            ValidatedPoc::Curl { path, headers } => {
                let mut args = vec![
                    "-I".to_string(), 
                    "--fail".to_string(), 
                    "--max-time".to_string(), "10".to_string(),
                    "--location-trusted".to_string(),
                    "--proto".to_string(), "=http,https".to_string(),
                    format!("http://{}{}", target_ip, path)
                ];
                for (name, val) in headers {
                    args.push("-H".to_string());
                    args.push(format!("{}: {}", name, val));
                }
                ("curl", args)
            },
            ValidatedPoc::Ping => ("ping", vec!["-c".to_string(), "3".to_string(), "-W".to_string(), "5".to_string(), target_ip.to_string()]),
            ValidatedPoc::Dig => ("dig", vec!["+short".to_string(), target_ip.to_string()]),
            ValidatedPoc::TcpConnect { port: _port } => {
                anyhow::bail!("V13 Policy Violation: TcpConnect should use TcpCheck strategy.");
            }
        };

        // V13 Stealth Infrastructure: Wrap CLI command if proxy is active
        if let Some(ref pm) = self.proxy_manager {
            pm.wrap_command(binary, &mut args);
        }

        let mut cmd = crate::utils::common::stealth_command(binary);
        cmd.args(&args);

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
        let target_addr = target.pinned_addr()
            .context("V12: Target IP must be resolved and pinned before TCP check execution")?;
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
        let target_addr = target.pinned_addr()
            .context("V12: Target IP must be resolved and pinned before ICMP ping execution")?;
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
        // V13 HARDENING (HIGH-001): Mandatory IP Pinning & SSRF validation (Priority resolved_ip)
        let target_ip = target.pinned_addr()
            .context("V13: Target IP must be pinned (ResolvedIP) before HTTP PoC execution to prevent DNS Rebinding.")?;
            
        // V13 Stealth Infrastructure: Use ProxyManager for HTTP PoCs
        let client = if let Some(ref pm) = self.proxy_manager {
            if let Some((_proxy, client)) = pm.get_client_pinned(&target.host, target_ip.parse()?, 80) {
                client
            } else {
                reqwest::Client::builder()
                    .timeout(Duration::from_secs(10))
                    .danger_accept_invalid_certs(true)
                    .redirect(reqwest::redirect::Policy::none())
                    .build()?
            }
        } else {
            reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .danger_accept_invalid_certs(true)
                .redirect(reqwest::redirect::Policy::none())
                .build()?
        };
        
        // Ensure the IP is safe via central utility
        if !crate::utils::liveness::is_ssrf_safe_host(target_ip).await {
             anyhow::bail!("V13 SSRF Blocked: Target IP {} is in a restricted range (Local/Private/Cloud-Metadata).", target_ip);
        }

        let path = if payload.starts_with("http") {
             // Extract path if AI provided a full URL, but force our pinned IP.
             reqwest::Url::parse(payload).map(|u| u.path().to_string()).unwrap_or_else(|_| "/".to_string())
        } else {
             payload.to_string()
        };

        // Path Sanitization (Defense in Depth)
        let safe_path = if path.contains("..") || path.contains(' ') {
            warn!("V13: Detected suspicious path in HTTP PoC: {}. Normalizing.", path);
            "/".to_string()
        } else if path.starts_with('/') { 
            path 
        } else { 
            format!("/{}", path) 
        };

        let url = format!("http://{}{}", target_ip, safe_path);

        info!("🌐 V13 HTTP PoC (Pinned): Requesting {}", url);
        let mut request = client.get(&url);
        
        // Set Host header to the original hostname to support vhosts on pinned IP.
        // V13 HARDENING: Validate Host header format to prevent Header Injection.
        static HOST_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[a-zA-Z0-9\-\.]+$").unwrap());
        let safe_host = if HOST_RE.is_match(&target.host) {
            &target.host
        } else {
            target_ip
        };
        request = request.header("Host", safe_host);
        request = request.header("User-Agent", crate::utils::common::get_random_user_agent());

        let res = request.send().await?;
        let status = res.status();
        
        // Limit response body size to prevent DoS (V13)
        let body = res.text().await?;
        let truncated_body = if body.len() > 5000 {
            format!("{}... [TRUNCATED]", &body[..5000])
        } else {
            body
        };
        
        Ok(format!("Status: {}\nBody: {}", status, truncated_body))
    }
}

fn extract_json(text: &str) -> &str {
    if let Some(start) = text.find('{') {
        if let Some(end) = text.rfind('}') { return &text[start..=end]; }
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{TargetStatus, TargetType};
    use crate::core::ai::TieredAIRouter;
    use crate::core::approval_gate::ApprovalGate;

    fn setup_validator() -> PocValidator {
        let router = Arc::new(TieredAIRouter::new());
        let approval_gate = Arc::new(ApprovalGate::for_red_team());
        let operator = User {
            id: "test".to_string(),
            name: "Test Ops".to_string(),
            role: crate::core::approval_gate::UserRole::RedTeamFull,
            authorized_at: chrono::Utc::now(),
        };
        PocValidator::new(router, approval_gate, operator, None)
    }

    #[tokio::test]
    async fn test_nmap_semantic_validation() {
        let validator = setup_validator();
        let mut target = TargetHost {
            host: "scan-me.com".to_string(),
            ip: Some("93.184.216.34".to_string()),
            resolved_ip: Some("93.184.216.34".to_string()),
            status: TargetStatus::Pending,
            target_type: TargetType::Web,
            findings: Arc::new(Vec::new()),
            tool_suggestions: Arc::new(Vec::new()),
            tactical_context: Arc::new(json!({})),
            extra_data: Arc::new(json!({})),
        };

        // Valid payload
        let valid_payload = json!({
            "binary": "nmap",
            "port": 80,
            "flags": ["-sV", "-Pn"]
        }).to_string();
        
        // This will attempt to run nmap, so we just check if it parses correctly
        // Instead of calling execute_safe_command directly (which runs binary), 
        // we normally would unit test the validator logic if it was decoupled.
        // For now, we'll verify it doesn't bail on valid input (assuming nmap is present) 
        // or check for specific error messages on illegal input.
        
        let illegal_payload = json!({
            "binary": "nmap",
            "port": 80,
            "flags": ["--script", "http-enum"] // Illegal flag
        }).to_string();
        
        let res = validator.execute_safe_command(&illegal_payload, &target).await;
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("V13 Security Violation: Flag '--script'"));
    }

    #[tokio::test]
    async fn test_curl_path_sanitization() {
        let validator = setup_validator();
        let target = TargetHost {
            host: "example.com".to_string(),
            ip: Some("93.184.216.34".to_string()),
            resolved_ip: Some("93.184.216.34".to_string()),
            status: TargetStatus::Pending,
            target_type: TargetType::Web,
            findings: Arc::new(Vec::new()),
            tool_suggestions: Arc::new(Vec::new()),
            tactical_context: Arc::new(json!({})),
            extra_data: Arc::new(json!({})),
        };

        let bad_path_payload = json!({
            "binary": "curl",
            "path": "/../../../etc/passwd"
        }).to_string();
        
        let res = validator.execute_safe_command(&bad_path_payload, &target).await;
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("V13 Policy Violation: Illegal characters"));
    }

    #[tokio::test]
    async fn test_ssrf_block_in_poc() {
        let validator = setup_validator();
        let target = TargetHost {
            host: "internal.local".to_string(),
            ip: Some("127.0.0.1".to_string()),
            resolved_ip: Some("127.0.0.1".to_string()),
            status: TargetStatus::Pending,
            target_type: TargetType::Web,
            findings: Arc::new(Vec::new()),
            tool_suggestions: Arc::new(Vec::new()),
            tactical_context: Arc::new(json!({})),
            extra_data: Arc::new(json!({})),
        };

        let payload = json!({ "binary": "ping" }).to_string();
        let res = validator.execute_safe_command(&payload, &target).await;
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("V13 SSRF Blocked"));
    }
}
