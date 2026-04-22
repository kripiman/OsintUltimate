use crate::utils::{stealth_http::StealthClientBuilder, proxy::ProxyManager};
use crate::core::ai::TieredAIRouter;
use crate::models::{Finding, ValidationStatus, ValidationMetadata, TargetHost, Severity};

use crate::core::verification::interaction::OobInteractionManager;
use anyhow::Result;
use chrono::Utc;
use std::sync::Arc;
use tracing::{info, warn, error};
use serde_json::Value;

/// V15: ANTI-HALLUCINATION PIPELINE
/// Implements a multi-layered verification strategy inspired by NeuroSploit.
pub struct ValidationPipeline;

impl ValidationPipeline {
    /// Layer 1: Negative Control
    /// Verifies if the finding persists when the "suspicious" tokens are replaced with benign ones.
    pub async fn check_negative_control(
        finding: &Finding,
        target: &TargetHost,
        proxy_manager: &ProxyManager,
    ) -> Result<bool> {
        let evidence = &finding.evidence.data;
        
        let url = match evidence.get("url").and_then(|v| v.as_str()) {
            Some(u) => u,
            None => {
                warn!("[Validation] No URL found in evidence for Negative Control.");
                return Ok(true); // Can't disprove, so assume passed baseline
            }
        };

        let method = evidence.get("method").and_then(|v| v.as_str()).unwrap_or("GET");
        let payload = evidence.get("payload").and_then(|v| v.as_str()).unwrap_or("");

        if payload.is_empty() {
             return Ok(true);
        }

        // 1. Create Benign Payload
        let benign_payload = Self::benignify(payload);
        
        // 2. Perform Benign Request
        info!("🧬 [Validation] Layer 1: Performing Negative Control with benign payload: '{}'", benign_payload);
        let client = StealthClientBuilder::build(target, proxy_manager)?;
        
        // Replace payload in URL if it's GET, or in body if POST
        let benign_url = url.replace(payload, &benign_payload);
        let res = client.request(method.parse()?, &benign_url).send().await?;
        let status = res.status();
        let body = res.text().await.unwrap_or_default();

        // 3. Validation Logic: 
        // If the vulnerability signature (e.g. 500 error, reflection, or specific pattern) 
        // is EXACTLY the same with the benign payload, then it's a False Positive.
        let original_status = evidence.get("response_status").and_then(|v| v.as_u64()).unwrap_or(200) as u16;
        let expected_pattern = evidence.get("expected_pattern").and_then(|v| v.as_str()).unwrap_or("");

        if status.as_u16() == original_status && !expected_pattern.is_empty() && body.contains(expected_pattern) {
            warn!("❌ [Validation] Negative Control FAILED: Benign request produced same 'vulnerability' signature.");
            return Ok(false);
        }

        Ok(true)
    }

    /// Layer 2: Proof of Execution
    /// Deep check for technical artifacts of success. Focused on High/Critical findings.
    pub async fn verify_proof(
        finding: &Finding,
        target: &TargetHost,
        proxy_manager: &ProxyManager,
    ) -> Result<Option<String>> {
        if finding.severity < Severity::High {
            return Ok(None);
        }

        let category = format!("{:?}", finding.category).to_lowercase();
        let evidence = &finding.evidence.data;

        // SQL Injection Handler
        if category.contains("vulnerability") && finding.title.to_lowercase().contains("sqli") {
            return Ok(Self::verify_sqli(evidence, target, proxy_manager).await);
        }

        // LFI Handler
        if finding.title.to_lowercase().contains("lfi") || finding.title.to_lowercase().contains("inclusion") {
            return Ok(Self::verify_lfi(evidence).await);
        }

        // RCE Handler
        if finding.title.to_lowercase().contains("rce") || finding.title.to_lowercase().contains("execution") {
             return Ok(Self::verify_rce(evidence).await);
        }

        // XSS Handler
        if finding.title.to_lowercase().contains("xss") {
             return Ok(Self::verify_xss(evidence).await);
        }

        Ok(None)
    }

    async fn verify_sqli(evidence: &Value, _target: &TargetHost, _pm: &ProxyManager) -> Option<String> {
        let timing = evidence.get("time_taken_ms").and_then(|v| v.as_u64()).unwrap_or(0);
        if timing > 5000 {
            return Some(format!("Confirmed SQLi via time-delay signature ({}ms).", timing));
        }
        
        let body = evidence.get("response_body").and_then(|v| v.as_str()).unwrap_or("");
        let sql_errors = ["sql syntax", "mysql_fetch", "ora-00933", "postgresql error", "sqlite3::memory"];
        for err in sql_errors {
            if body.to_lowercase().contains(err) {
                 return Some(format!("Confirmed SQLi via error-based signature: '{}'", err));
            }
        }
        None
    }

    async fn verify_lfi(evidence: &Value) -> Option<String> {
        let body = evidence.get("response_body").and_then(|v| v.as_str()).unwrap_or("");
        if body.contains("root:x:0:0:") || body.contains("[extensions]") || body.contains("boot loader") {
            return Some("Confirmed LFI via system file marker detection (/etc/passwd or win.ini).".to_string());
        }
        None
    }

    async fn verify_rce(evidence: &Value) -> Option<String> {
        let body = evidence.get("response_body").and_then(|v| v.as_str()).unwrap_or("");
        if body.contains("uid=") && body.contains("gid=") || body.contains("Windows IP Configuration") {
            return Some("Confirmed RCE via command output verification (id/ipconfig).".to_string());
        }
        None
    }

    async fn verify_xss(evidence: &Value) -> Option<String> {
        let body = evidence.get("response_body").and_then(|v| v.as_str()).unwrap_or("");
        let nonce = evidence.get("nonce").and_then(|v| v.as_str()).unwrap_or("");
        if !nonce.is_empty() && body.contains(&format!("<script>confirm('{}')</script>", nonce)) {
            return Some("Confirmed XSS via exact nonce reflection in script context.".to_string());
        }
        None
    }

    /// Layer 4: OOB Verification
    /// Captures interactions from external servers (SSRF, Blind RCE, etc.)
    pub async fn check_oob_verification(
        finding: &Finding,
        target: &TargetHost,
        proxy_manager: Arc<ProxyManager>,
    ) -> Result<Option<String>> {
        let category = format!("{:?}", finding.category).to_lowercase();
        let title = finding.title.to_lowercase();
        let evidence = &finding.evidence.data;
        
        let is_oob_capable = category.contains("vulnerability") && (
            title.contains("ssrf") || 
            title.contains("oob") || 
            title.contains("blind") ||
            finding.severity >= Severity::High
        );

        if !is_oob_capable {
            return Ok(None);
        }

        let om = OobInteractionManager::new(proxy_manager.clone());
        
        // --- Part 1: Retrospective Check ---
        if let Some(id) = evidence.get("oob_id").and_then(|v| v.as_str()) {
            info!("🧬 [OOB] checking retrospective hit for existing ID: {}", id);
            if let Some(hit) = om.wait_for_interaction(id, 5).await? {
                 return Ok(Some(format!("Confirmed OOB interaction ({}) via Retrospective ID: {}", hit.protocol, id)));
            }
        }

        // --- Part 2: Proactive Re-execution (V15.5) ---
        let fresh_id = om.generate_id();
        
        let url = evidence.get("url").and_then(|v| v.as_str());
        let payload = evidence.get("payload").and_then(|v| v.as_str());
        let method = evidence.get("method").and_then(|v| v.as_str()).unwrap_or("GET");

        if let (Some(u), Some(p)) = (url, payload) {
            info!("🧬 [OOB] Proactive Re-execution: Triggering fresh PoC with ID: {}...", fresh_id);
            
            // Inyect fresh domain into payload
            // This assumes the payload had a placeholder or a domain that can be replaced
            let fresh_payload = if p.contains(".interactsh.com") {
                // Replace old domain with fresh one
                p.split('.').next().map(|prefix| p.replace(prefix, &fresh_id)).unwrap_or_else(|| p.to_string())
            } else {
                p.to_string() // Or append if it's a blind param
            };

            let fresh_url = u.replace(p, &fresh_payload);
            let client = StealthClientBuilder::build(target, &proxy_manager)?;
            
            // Fire and forget the request (don't wait for response, wait for the OOB HIT)
            let _ = client.request(method.parse()?, &fresh_url).send().await;
            
            // Poll for interaction
            if let Some(hit) = om.wait_for_interaction(&fresh_id, 30).await? {
                return Ok(Some(format!("Confirmed OOB interaction ({}) via PROACTIVE ID: {}", hit.protocol, fresh_id)));
            }
        }

        Ok(None)
    }

    /// Layer 3: AI Judge
    /// Orchestrates Layers 1, 2 & 4 and uses high-reasoning logic.
    pub async fn validate(
        finding: &mut Finding,
        target: &TargetHost,
        proxy_manager: Arc<ProxyManager>,
        router: Arc<TieredAIRouter>,
    ) -> Result<()> {
        info!("🔍 [Validation] Invocando Pipeline Anti-Alucinación (V15) para: {}", finding.id);
        
        let neg_control = Self::check_negative_control(finding, target, &proxy_manager).await
            .unwrap_or_else(|e| {
                error!("[Validation] Error in Layer 1: {}", e);
                true // Assume passed to avoid blocking on network errors
            });

        let proof = Self::verify_proof(finding, target, &proxy_manager).await
            .unwrap_or_else(|e| {
                error!("[Validation] Error in Layer 2: {}", e);
                None
            });
        
        let oob_proof = Self::check_oob_verification(finding, target, proxy_manager.clone()).await
            .unwrap_or_else(|e| {
                error!("[Validation] Error in Layer 4: {}", e);
                None
            });
        
        let status;
        let confidence;
        let notes;

        if !neg_control {
            status = ValidationStatus::PseudoFalse;
            confidence = 0.1;
            notes = "FAILED Negative Control: Evidence signature observed in benign conditions. Likely AI Hallucination or Static String.".to_string();
        } else if let Some(ref oob_msg) = oob_proof {
            status = ValidationStatus::Verified;
            confidence = 1.0;
            let p_msg = proof.as_ref().map(|s| format!(" | {}", s)).unwrap_or_default();
            notes = format!("PASSED OOB Verification: {}{}", oob_msg, p_msg);
        } else if let Some(ref proof_msg) = proof {
            status = ValidationStatus::Verified;
            confidence = 1.0;
            notes = format!("PASSED Proof of Execution: {}", proof_msg);
        } else if finding.severity >= Severity::High {
            // Layer 3: AI Judge Escalation (Only if NO technical proof was found)
            info!("🧠 [Validation] Layer 3: Escalating to Premium AI Judge for {} finding (No proof found).", finding.severity);
            
            let context = format!(
                "NegControlPassed: {}\nTechnicalProof: {:?}\nOOBProof: {:?}\nFindingTitle: {}\nEvidence: {:?}",
                neg_control, proof, oob_proof, finding.title, finding.evidence.data
            );

            // Per user request: Use Premium for High/Critical if they pass basic filters
            let verdict = router.analyze_with_level(
                finding, 
                target, 
                Some(&context), 
                crate::core::ai::RouteLevel::Premium,
                crate::core::ai::CavemanLevel::default()
            ).await?;

            if verdict.risk_score < 4 {
                status = ValidationStatus::PseudoFalse;
                confidence = 0.2;
                notes = format!("AI JUDGE REJECTED: {}", verdict.summary);
            } else {
                status = ValidationStatus::Verified;
                confidence = (verdict.confidence as f32).max(0.7);
                notes = format!("AI JUDGE VERIFIED: {} | {}", verdict.summary, verdict.stealth_notes);
            }
        } else {
            // Triage logic for lower severities
            status = ValidationStatus::Unverified;
            confidence = 0.5;
            notes = "PASSED Negative Control. Skipping Layer 2/3 for low/medium severity.".to_string();
        }

        finding.validation = ValidationMetadata {
            status,
            confidence_score: confidence,
            judge_notes: notes,
            negative_control_passed: neg_control,
            proof_of_execution: oob_proof.or(proof),
            validated_at: Some(Utc::now()),
        };

        if status == ValidationStatus::Verified {
            info!("✅ [Validation] Finding verificado con éxito.");
        } else if status == ValidationStatus::PseudoFalse {
             warn!("⚠️ [Validation] Finding marcado como FALSO POSITIVO (Layer 1).");
        }

        Ok(())
    }

    fn benignify(payload: &str) -> String {
        // V15.5 Hardening: Deep sanitization for multi-vector logic
        let mut b = payload.to_string();
        
        // 1. Strings & Encodings
        b = b.replace("'", "a").replace("\"", "b");
        b = b.replace("%27", "a").replace("%22", "b");
        b = b.replace("\\'", "a").replace("\\\"", "b");
        
        // 2. SQLi Logic
        b = b.replace("1=1", "1=2").replace("OR 1=1", "AND 0=1");
        b = b.replace("union select", "select");
        b = b.replace("SLEEP(", "ECHO(").replace("PG_SLEEP(", "ECHO(");
        b = b.replace("WAITFOR DELAY", "PRINT");
        
        // 3. XSS / Injection
        b = b.replace("<script>", "hello").replace("</script>", "world");
        b = b.replace("%3Cscript%3E", "hello");
        b = b.replace("eval(", "print(");
        
        // 4. Path Traversal
        b = b.replace("../", "./").replace("..\\", ".\\");
        b = b.replace("%2E%2E%2F", "./");
        
        // 5. OOB / Command
        b = b.replace("curl ", "echo ").replace("wget ", "echo ");
        b = b.replace("nslookup ", "echo ").replace("ping ", "echo ");
        
        // 6. Template Injection
        b = b.replace("{{", "{").replace("}}", "}");

        b
    }
}
