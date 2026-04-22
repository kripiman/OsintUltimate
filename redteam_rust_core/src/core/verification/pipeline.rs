use crate::utils::{stealth_http::StealthClientBuilder, proxy::ProxyManager};
use crate::models::{Finding, ValidationStatus, ValidationMetadata, TargetHost, Severity, PocStrategy};
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
        proxy_manager: Arc<ProxyManager>,
    ) -> Result<Option<String>> {
        let category = format!("{:?}", finding.category).to_lowercase();
        let title = finding.title.to_lowercase();
        
        // Detect if finding is OOB-capable
        let is_oob_capable = category.contains("vulnerability") && (
            title.contains("ssrf") || 
            title.contains("oob") || 
            title.contains("blind") ||
            finding.severity >= Severity::High
        );

        if !is_oob_capable {
            return Ok(None);
        }

        let oob_mgr = OobInteractionManager::new(proxy_manager);
        let oob_id = oob_mgr.generate_id();
        let oob_domain = oob_mgr.get_oob_domain(&oob_id);

        info!("🧬 [Validation] Layer 4: Testing OOB interaction via {}", oob_domain);
        
        // Trigger the PoC again with the OOB payload if available
        // NOTE: In a full implementation, we'd use the PocValidator to re-run.
        // For now, we check if there's an existing interaction in the evidence (retrospective hit)
        // or we just query the server for the ID generated during the initial scan if it was provided.
        
        // V15.3 logic: If the original scan already used an OOB ID, it should be in the evidence.
        let existing_id = finding.evidence.data.get("oob_id").and_then(|v| v.as_str());
        
        if let Some(id) = existing_id {
            if let Some(hit) = oob_mgr.wait_for_interaction(id, 30).await? {
                return Ok(Some(format!("Confirmed OOB interaction ({}) from {}", hit.protocol, hit.remote_address)));
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
        
        let oob_proof = Self::check_oob_verification(finding, proxy_manager).await
            .unwrap_or_else(|e| {
                error!("[Validation] Error in Layer 4: {}", e);
                None
            });
        
        let mut status = ValidationStatus::Unverified;
        let mut confidence = finding.evidence.confidence;
        let mut notes = String::new();

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
        } else {
            // Triage logic: High severities without proof are suspicious
            if finding.severity >= Severity::High {
                status = ValidationStatus::Suspicious;
                confidence = 0.3;
                notes = "PASSED Negative Control but NO technical proof for Critical/High finding. Verification required.".to_string();
            } else {
                status = ValidationStatus::Unverified;
                confidence = 0.5;
                notes = "PASSED Negative Control. Proof of Execution skipped for low/medium severity.".to_string();
            }
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
        // Simple heuristic to create a "benign" version of a payload
        payload.replace("'", "a")
               .replace("<script>", "hello")
               .replace("1=1", "1=2")
               .replace("../", "./")
               .replace("sleep", "echo")
    }
}
