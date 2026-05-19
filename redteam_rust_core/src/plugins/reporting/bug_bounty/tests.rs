use super::*;
use crate::models::{Evidence, Finding, Category, Severity, AIAnalysis};
use crate::models::findings::{FindingEvidence, PocDefinition, PocStrategy, TokenUsage};
use serde_json::json;

fn bare_finding() -> Finding {
    Finding::new("TEST_BARE", Category::Recon, Severity::High, "bare test", json!({}))
}

#[test]
fn test_triage_score_bare_is_zero() {
    let f = bare_finding();
    assert_eq!(triage_readiness_score(&f), 0);
}

#[test]
fn test_triage_score_request_adds_15() {
    let f = Finding::new("TEST_REQ", Category::Recon, Severity::High, "t",
        json!({"request": "GET / HTTP/1.1\r\nHost: x.com\r\n\r\n"}));
    assert_eq!(triage_readiness_score(&f), 15);
}

#[test]
fn test_triage_score_request_response_verified_is_40() {
    let mut f = bare_finding();
    f.evidence = FindingEvidence {
        primary: Some(Evidence {
            data: json!({"request": "GET / HTTP/1.1", "response": "HTTP/1.1 200 OK"}),
            confidence: 0.9,
            verified: true,
        }),
        files: vec![],
    };
    assert_eq!(triage_readiness_score(&f), 40); // 15+10+15
}

#[test]
fn test_triage_score_ai_enrichment_adds_30() {
    let mut f = bare_finding();
    f.enrichment.ai_analysis = Some(AIAnalysis {
        summary: "".into(),
        impact: "".into(),
        stealth_notes: "".into(),
        risk_score: 9,
        confidence: 0.95,
        mitre_attack: None,
        exploit_path: "curl -X POST /admin".into(),
        model: "llama3".into(),
        poc: Some(PocDefinition {
            strategy: PocStrategy::HttpPayload,
            payload: "XSS payload".into(),
            expected_pattern: "alert".into(),
            is_intrusive: false,
            complexity_score: 30,
        }),
        usage: TokenUsage::default(),
    });
    assert_eq!(triage_readiness_score(&f), 30); // 15+10+5
}

#[test]
fn test_triage_score_cvss_adds_20() {
    let mut f = bare_finding();
    f.enrichment.cvss_score = Some(8.5);
    f.enrichment.cvss_vector = Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".into());
    assert_eq!(triage_readiness_score(&f), 20); // 10+10
}

#[test]
fn test_triage_score_references_add_10() {
    let mut f = bare_finding();
    f.enrichment.references = vec!["https://nvd.nist.gov/vuln/detail/CVE-2024-1234".into()];
    assert_eq!(triage_readiness_score(&f), 10);
}

#[test]
fn test_triage_score_full_is_100() {
    let mut f = Finding::new("TEST_FULL", Category::Recon, Severity::Critical, "full",
        json!({"request": "GET / HTTP/1.1", "response": "HTTP/1.1 200 OK"}));
    f.evidence.primary.as_mut().unwrap().verified = true;
    f.enrichment.ai_analysis = Some(AIAnalysis {
        summary: "".into(),
        impact: "".into(),
        stealth_notes: "".into(),
        risk_score: 9,
        confidence: 0.95,
        mitre_attack: None,
        exploit_path: "curl -X POST /admin".into(),
        model: "llama3".into(),
        poc: Some(PocDefinition {
            strategy: PocStrategy::HttpPayload,
            payload: "payload".into(),
            expected_pattern: "alert".into(),
            is_intrusive: false,
            complexity_score: 30,
        }),
        usage: TokenUsage::default(),
    });
    f.enrichment.cvss_score = Some(9.8);
    f.enrichment.cvss_vector = Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".into());
    f.enrichment.references = vec!["https://example.com/ref".into()];
    assert_eq!(triage_readiness_score(&f), 100);
}

#[test]
fn test_triage_score_threshold_auto_submit() {
    // Minimum combination to reach 70: verified evidence (40) + AI exploit+risk (25) + cvss_score (10) = 75
    let mut f = bare_finding();
    f.evidence = FindingEvidence {
        primary: Some(Evidence {
            data: json!({"request": "GET /", "response": "HTTP/1.1 200 OK"}),
            confidence: 0.8,
            verified: true,
        }),
        files: vec![],
    };
    f.enrichment.ai_analysis = Some(AIAnalysis {
        summary: "".into(),
        impact: "".into(),
        stealth_notes: "".into(),
        risk_score: 7,
        confidence: 0.8,
        mitre_attack: None,
        exploit_path: "exploit chain".into(),
        model: "llama3".into(),
        poc: None,
        usage: TokenUsage::default(),
    });
    f.enrichment.cvss_score = Some(7.5);
    let score = triage_readiness_score(&f);
    assert!(score >= 70, "Expected auto-submit threshold met, got {score}");
}

#[test]
fn test_build_curl_get() {
    let raw = "GET /api/v1/user HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer secret\r\n\r\n";
    let curl = build_curl_from_raw(raw, "fallback.com").unwrap();
    assert!(curl.contains("-X GET"));
    assert!(curl.contains("-H \"Authorization: Bearer secret\""));
    assert!(curl.contains("'https://example.com/api/v1/user'"));
}

#[test]
fn test_build_curl_post_json() {
    let raw = "POST /login HTTP/1.1\nHost: target.local\nContent-Type: application/json\n\n{\"user\":\"admin\"}";
    let curl = build_curl_from_raw(raw, "fallback.com").unwrap();
    assert!(curl.contains("-X POST"));
    assert!(curl.contains("--data-raw '{\"user\":\"admin\"}'"));
    assert!(curl.contains("'https://target.local/login'"));
}
