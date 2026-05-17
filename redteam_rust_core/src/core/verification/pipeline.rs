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
    pub async fn check_negative_control(
        finding: &Finding,
        target: &TargetHost,
        proxy_manager: &ProxyManager,
    ) -> Result<bool> {
        let evidence_data = finding.evidence.primary.as_ref();
        let evidence = match evidence_data {
            Some(e) => &e.data,
            None => {
                warn!("[Validation] No evidence found for Negative Control.");
                return Ok(true);
            }
        };
        
        let url = match evidence.get("url").and_then(|v| v.as_str()) {
            Some(u) => u,
            None => {
                warn!("[Validation] No URL found in evidence for Negative Control.");
                return Ok(true); 
            }
        };

        let method = evidence.get("method").and_then(|v| v.as_str()).unwrap_or("GET");
        let payload = evidence.get("payload").and_then(|v| v.as_str()).unwrap_or("");

        if payload.is_empty() {
             return Ok(true);
        }

        let benign_payload = Self::benignify(payload);
        
        info!("🧬 [Validation] Layer 1: Performing Negative Control with benign payload: '{}'", benign_payload);
        let client = StealthClientBuilder::build(target, proxy_manager)?;
        
        let benign_url = url.replace(payload, &benign_payload);
        let res_val: Result<reqwest::Response, reqwest::Error> = client.request(method.parse()?, &benign_url).send().await;
        if let Ok(res) = res_val {
            let status = res.status();
            let body = res.text().await.unwrap_or_default();

            let original_status = evidence.get("response_status").and_then(|v| v.as_u64()).unwrap_or(200) as u16;
            let expected_pattern = evidence.get("expected_pattern").and_then(|v| v.as_str()).unwrap_or("");

            if status.as_u16() == original_status && !expected_pattern.is_empty() && body.contains(expected_pattern) {
                warn!("❌ [Validation] Negative Control FAILED: Benign request produced same 'vulnerability' signature.");
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Layer 2: Proof of Execution
    pub async fn verify_proof(
        finding: &Finding,
        target: &TargetHost,
        proxy_manager: &ProxyManager,
    ) -> Result<Option<String>> {
        if finding.core.severity < Severity::High {
            return Ok(None);
        }

        let category = format!("{:?}", finding.core.category).to_lowercase();
        let evidence_data = finding.evidence.primary.as_ref();
        let evidence = match evidence_data {
            Some(e) => &e.data,
            None => return Ok(None),
        };

        if category.contains("vulnerability") && finding.core.title.to_lowercase().contains("sqli") {
            return Ok(Self::verify_sqli(evidence, target, proxy_manager).await);
        }

        if finding.core.title.to_lowercase().contains("lfi") || finding.core.title.to_lowercase().contains("inclusion") {
            return Ok(Self::verify_lfi(evidence).await);
        }

        if finding.core.title.to_lowercase().contains("rce") || finding.core.title.to_lowercase().contains("execution") {
             return Ok(Self::verify_rce(evidence).await);
        }

        if finding.core.title.to_lowercase().contains("xss") {
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
    pub async fn check_oob_verification(
        finding: &Finding,
        target: &TargetHost,
        proxy_manager: Arc<ProxyManager>,
    ) -> Result<Option<String>> {
        let category = format!("{:?}", finding.core.category).to_lowercase();
        let title = finding.core.title.to_lowercase();
        let evidence_data = finding.evidence.primary.as_ref();
        let evidence = match evidence_data {
            Some(e) => &e.data,
            None => return Ok(None),
        };
        
        let is_oob_capable = category.contains("vulnerability") && (
            title.contains("ssrf") || 
            title.contains("oob") || 
            title.contains("blind") ||
            finding.core.severity >= Severity::High
        );

        if !is_oob_capable {
            return Ok(None);
        }

        let om = OobInteractionManager::new(proxy_manager.clone());
        
        if let Some(id) = evidence.get("oob_id").and_then(|v| v.as_str()) {
            info!("🧬 [OOB] checking retrospective hit for existing ID: {}", id);
            if let Some(hit) = om.wait_for_interaction(id, 5).await? {
                 return Ok(Some(format!("Confirmed OOB interaction ({}) via Retrospective ID: {}", hit.protocol, id)));
            }
        }

        let fresh_id = om.generate_id();
        
        let url = evidence.get("url").and_then(|v| v.as_str());
        let payload = evidence.get("payload").and_then(|v| v.as_str());
        let method = evidence.get("method").and_then(|v| v.as_str()).unwrap_or("GET");

        if let (Some(u), Some(p)) = (url, payload) {
            info!("🧬 [OOB] Proactive Re-execution: Triggering fresh PoC with ID: {}...", fresh_id);
            
            let fresh_payload = if p.contains(".interactsh.com") {
                p.split('.').next().map(|prefix| p.replace(prefix, &fresh_id)).unwrap_or_else(|| p.to_string())
            } else {
                p.to_string()
            };

            let fresh_url = u.replace(p, &fresh_payload);
            let client = StealthClientBuilder::build(target, &proxy_manager)?;
            let _ = client.request(method.parse()?, &fresh_url).send().await;
            
            if let Some(hit) = om.wait_for_interaction(&fresh_id, 30).await? {
                return Ok(Some(format!("Confirmed OOB interaction ({}) via PROACTIVE ID: {}", hit.protocol, fresh_id)));
            }
        }

        Ok(None)
    }

    /// Layer 3: AI Judge
    pub async fn validate(
        finding: &mut Finding,
        target: &TargetHost,
        proxy_manager: Arc<ProxyManager>,
        router: Arc<TieredAIRouter>,
    ) -> Result<()> {
        info!("🔍 [Validation] Invocando Pipeline Anti-Alucinación (V15) para: {}", finding.core.id);
        
        let neg_control = Self::check_negative_control(finding, target, &proxy_manager).await
            .unwrap_or_else(|e| {
                error!("[Validation] Error in Layer 1: {}", e);
                true 
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
        } else if finding.core.severity >= Severity::High {
            info!("🧠 [Validation] Layer 3: Escalating to Premium AI Judge for {} finding (No proof found).", finding.core.severity);
            
            let evidence_data = finding.evidence.primary.as_ref().map(|e| &e.data);
            let context = format!(
                "NegControlPassed: {}\nTechnicalProof: {:?}\nOOBProof: {:?}\nFindingTitle: {}\nEvidence: {:?}",
                neg_control, proof, oob_proof, finding.core.title, evidence_data
            );

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
            status = ValidationStatus::Unverified;
            confidence = 0.5;
            notes = "PASSED Negative Control. Skipping Layer 2/3 for low/medium severity.".to_string();
        }

        finding.validation = Some(ValidationMetadata {
            status,
            confidence_score: confidence,
            judge_notes: notes,
            negative_control_passed: neg_control,
            proof_of_execution: oob_proof.or(proof),
            validated_at: Some(Utc::now()),
        });

        if status == ValidationStatus::Verified {
            info!("✅ [Validation] Finding verificado con éxito.");
        } else if status == ValidationStatus::PseudoFalse {
             warn!("⚠️ [Validation] Finding marcado como FALSO POSITIVO (Layer 1).");
        }

        Ok(())
    }

    fn benignify(payload: &str) -> String {
        let mut b = payload.to_string();
        b = b.replace("'", "a").replace("\"", "b");
        b = b.replace("%27", "a").replace("%22", "b");
        b = b.replace("\\'", "a").replace("\\\"", "b");
        b = b.replace("1=1", "1=2").replace("OR 1=1", "AND 0=1");
        b = b.replace("union select", "select");
        b = b.replace("SLEEP(", "ECHO(").replace("PG_SLEEP(", "ECHO(");
        b = b.replace("WAITFOR DELAY", "PRINT");
        b = b.replace("<script>", "hello").replace("</script>", "world");
        b = b.replace("%3Cscript%3E", "hello");
        b = b.replace("eval(", "print(");
        b = b.replace("../", "./").replace("..\\", ".\\");
        b = b.replace("%2E%2E%2F", "./");
        b = b.replace("curl ", "echo ").replace("wget ", "echo ");
        b = b.replace("nslookup ", "echo ").replace("ping ", "echo ");
        b = b.replace("{{", "{").replace("}}", "}");
        b
    }
}
