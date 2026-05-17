/// Bug Bounty report generator — produces one Markdown file per finding,
/// formatted for HackerOne / Bugcrowd triage requirements.
use crate::models::{Finding, Severity, TargetHost, Category};
use std::fmt::Write;

pub struct BugBountyReport {
    pub filename: String,
    pub content: String,
}

/// V14.7: 0-100 Triage Readiness Score. Gates auto-submit (≥70) vs manual review vs do-not-submit.
/// pub(crate) so BountySink can import without re-exposing publicly.
pub(crate) fn triage_readiness_score(finding: &Finding) -> u8 {
    let mut score: u16 = 0;

    // Evidence quality (40 pts)
    if finding.evidence.primary.as_ref()
        .and_then(|e| e.data.get("request")).is_some() { score += 15; }
    if finding.evidence.primary.as_ref()
        .and_then(|e| e.data.get("response")).is_some() { score += 10; }
    if finding.evidence.primary.as_ref()
        .map(|e| e.verified).unwrap_or(false) { score += 15; }

    // AI enrichment (30 pts)
    if let Some(ref ai) = finding.enrichment.ai_analysis {
        if !ai.exploit_path.is_empty() { score += 15; }
        if ai.risk_score > 0 { score += 10; }
        if ai.poc.as_ref().map(|p| !p.payload.is_empty()).unwrap_or(false) { score += 5; }
    }

    // CVSS (20 pts)
    if finding.enrichment.cvss_score.is_some() { score += 10; }
    if finding.enrichment.cvss_vector.is_some() { score += 10; }

    // References proxy for remediation guidance (10 pts)
    // A finding with CVE/CWE URLs listed is more report-ready.
    if !finding.enrichment.references.is_empty() { score += 10; }

    score.min(100) as u8
}

/// Generates one report per finding that is Medium severity or above.
pub fn generate_reports(target: &TargetHost) -> Vec<BugBountyReport> {
    target.findings.iter()
        .filter(|f| matches!(f.core.severity, Severity::Critical | Severity::High | Severity::Medium))
        .map(|f| build_report(target, f))
        .collect()
}

fn build_report(target: &TargetHost, finding: &Finding) -> BugBountyReport {
    let slug = finding.core.id.to_lowercase().replace(['_', ' '], "-");
    let filename = format!("{}_{}.md", target.host.replace('.', "_"), slug);

    let mut md = String::new();

    // Title
    let title_prefix = if finding.enrichment.is_new { "[NEW] " } else { "" };
    let _ = writeln!(md, "# {}{}", title_prefix, finding.core.title);
    let _ = writeln!(md);

    // Metadata table
    let _ = writeln!(md, "| Field | Value |");
    let _ = writeln!(md, "|---|---|");
    let _ = writeln!(md, "| **Discovery** | {} |", if finding.enrichment.is_new { "New ✨" } else { "Historical 🕰️" });
    let _ = writeln!(md, "| **Severity** | {} |", severity_label(&finding.core.severity));
    // V14.7: Triage Readiness Score — rendered before CVSS to guide triage decision
    let readiness = triage_readiness_score(finding);
    let readiness_label = match readiness {
        70..=100 => "✅ Auto-Submit Ready",
        40..=69  => "⚠️ Manual Review",
        _        => "🔴 Incomplete — Do Not Submit",
    };
    let _ = writeln!(md, "| **Triage Readiness** | {}/100 — {} |", readiness, readiness_label);
    if let Some(score) = finding.enrichment.cvss_score {
        let _ = writeln!(md, "| **CVSS Score** | {:.1} |", score);
    }
    // V14.7: CVSS vector string (already populated by findings.rs, previously never rendered)
    if let Some(ref vector) = finding.enrichment.cvss_vector {
        let _ = writeln!(md, "| **CVSS Vector** | `{}` |", vector);
    }
    let _ = writeln!(md, "| **Asset** | `{}` |", target.host);
    if let Some(ip) = &target.ip {
        let _ = writeln!(md, "| **IP** | `{}` |", ip);
    }
    let _ = writeln!(md, "| **Finding ID** | `{}` |", finding.core.id);
    if let Some(mitre) = &finding.enrichment.mitre_attack {
        let _ = writeln!(md, "| **MITRE ATT&CK** | {} |", mitre.join(", "));
    }
    // Validation status
    let validated = finding.evidence.primary.as_ref().map(|e| e.verified).unwrap_or(false);
    let _ = writeln!(md, "| **Validation** | {} |",
        if validated { "Verified ✅" } else { "Potential 🔍" });

    // Risk score (only if AI analysis present)
    if let Some(ai) = &finding.enrichment.ai_analysis {
        if ai.risk_score > 0 {
            let _ = writeln!(md, "| **Risk Score** | {}/100 |", ai.risk_score);
        }
        if ai.confidence > 0.0 {
            let _ = writeln!(md, "| **AI Confidence** | {:.0}% |",
                ai.confidence * 100.0);
        }
    }
    let _ = writeln!(md);

    // Description
    let _ = writeln!(md, "## Description");
    let _ = writeln!(md);
    let _ = writeln!(md, "{}", finding.core.description);
    let _ = writeln!(md);

    // Impact — use AI analysis if available, otherwise derive from severity
    let _ = writeln!(md, "## Impact");
    let _ = writeln!(md);
    if let Some(ai) = &finding.enrichment.ai_analysis {
        let _ = writeln!(md, "{}", ai.impact);
    } else {
        let _ = writeln!(md, "{}", default_impact(&finding.core.severity));
    }
    let _ = writeln!(md);
    let _ = writeln!(md, "## Steps to Reproduce");
    let _ = writeln!(md);

    let evidence_data = finding.evidence.primary.as_ref();
    let evidence = http_evidence_view(finding);
    let curl_cmd = evidence.raw_request.and_then(|r| build_curl_from_raw(r, &target.host));

    if let Some(curl) = curl_cmd {
        let _ = writeln!(md, "1. Execute the following `curl` command to reproduce the finding:");
        let _ = writeln!(md, "   ```bash");
        let _ = writeln!(md, "   {}", curl);
        let _ = writeln!(md, "   ```");
        let _ = writeln!(md, "2. Observe that the response contains the vulnerability pattern described above.");
    } else {
        let matched_at = evidence_data
            .and_then(|e| e.data.get("matched_at"))
            .and_then(|v| v.as_str())
            .unwrap_or(&target.host);
        let template_id = evidence_data
            .and_then(|e| e.data.get("template_id"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let _ = writeln!(md, "1. Navigate to or send a request to: `{}`", matched_at);
        if !template_id.is_empty() {
            let _ = writeln!(md, "2. The vulnerability was detected via Nuclei template: `{}`", template_id);
        }
        let _ = writeln!(md, "3. Observe the response matches the vulnerability pattern described above.");
    }
    let _ = writeln!(md);

    // PoC evidence
    let _ = writeln!(md, "## Proof of Concept");
    let _ = writeln!(md);

    if let (Some(req), Some(res)) = (evidence.raw_request, evidence.raw_response) {
        let _ = writeln!(md, "### Raw Request");
        let _ = writeln!(md, "```http");
        let _ = writeln!(md, "{}", req);
        let _ = writeln!(md, "```");
        let _ = writeln!(md);
        let _ = writeln!(md, "### Raw Response");
        let _ = writeln!(md, "```http");
        let _ = writeln!(md, "{}", res);
        let _ = writeln!(md, "```");
    } else {
        let _ = writeln!(md, "```json");
        if let Some(e) = evidence_data {
            let _ = writeln!(md, "{}", serde_json::to_string_pretty(&e.data).unwrap_or_default());
        }
        let _ = writeln!(md, "```");
    }
    let _ = writeln!(md);

    // AI-generated PoC payload (from PocValidator)
    if let Some(ai) = &finding.enrichment.ai_analysis {
        if let Some(poc) = &ai.poc {
            let _ = writeln!(md, "### AI-Generated PoC");
            let _ = writeln!(md, "```");
            let _ = writeln!(md, "{}", poc.payload);
            let _ = writeln!(md, "```");
            let _ = writeln!(md);
        }
    }

    // Exploit Path
    let _ = writeln!(md, "## Exploit Path");
    let _ = writeln!(md);
    if let Some(ai) = &finding.enrichment.ai_analysis {
        let _ = writeln!(md, "{}", ai.exploit_path);
    } else {
        let _ = writeln!(md, "Please refer to the PoC evidence to understand the exploit step-by-step.");
    }
    let _ = writeln!(md);

    // Operator-only note — strip before submitting to platform
    if let Some(ai) = &finding.enrichment.ai_analysis {
        if !ai.stealth_notes.is_empty() {
            let _ = writeln!(md, "> **[Operator Note — remove before submission]** {}",
                ai.stealth_notes);
            let _ = writeln!(md);
        }
    }

    // Remediation
    let _ = writeln!(md, "## Remediation");
    let _ = writeln!(md);
    let _ = writeln!(md, "{}", default_remediation(&finding.core.severity, &finding.core.category));
    let _ = writeln!(md);

    // References
    if !finding.enrichment.references.is_empty() {
        let _ = writeln!(md, "## References");
        let _ = writeln!(md);
        for r in &finding.enrichment.references {
            let _ = writeln!(md, "- {}", r);
        }
        let _ = writeln!(md);
    }

    BugBountyReport { filename, content: md }
}

/// Generates a consolidated report for a group of related findings (Attack Chain).
pub fn generate_attack_chain_report(target: &TargetHost, findings: &[Finding]) -> Option<BugBountyReport> {
    if findings.is_empty() { return None; }
    
    let filename = format!("{}_attack_chain_consolidated.md", target.host.replace('.', "_"));
    let mut md = String::new();

    let _ = writeln!(md, "# 🔗 Consolidated Attack Chain Report: {}", target.host);
    let _ = writeln!(md);

    let _ = writeln!(md, "## 0. Executive Summary");
    let _ = writeln!(md, "This report documents a correlated sequence of vulnerabilities discovered on `{}`. ", target.host);
    let _ = writeln!(md, "By chaining these findings, an attacker can achieve a significantly higher impact than through isolated exploitation.");
    let _ = writeln!(md);

    let _ = writeln!(md, "## 1. Attack Chain Visualization");
    let _ = writeln!(md, "```mermaid");
    let _ = writeln!(md, "graph TD");
    for (i, f) in findings.iter().enumerate() {
        let _ = writeln!(md, "    F{}[{}]", i, f.core.title);
        if i > 0 {
            let _ = writeln!(md, "    F{} --> F{}", i-1, i);
        }
    }
    let _ = writeln!(md, "```");
    let _ = writeln!(md);

    let _ = writeln!(md, "## 2. Findings Summary");
    let _ = writeln!(md, "| Step | Finding | Severity | Category |");
    let _ = writeln!(md, "|---|---|---|---|");
    for (i, f) in findings.iter().enumerate() {
        let _ = writeln!(md, "| {} | **{}** | {} | {:?} |", i+1, f.core.title, severity_label(&f.core.severity), f.core.category);
    }
    let _ = writeln!(md);

    let _ = writeln!(md, "## 3. Combined Impact");
    // If AI analysis is present in any finding, use it to bolster the impact
    let mut combined_impact = String::new();
    for f in findings {
        if let Some(ai) = &f.enrichment.ai_analysis {
            combined_impact.push_str(&format!("- **{}**: {}\n", f.core.title, ai.impact));
        }
    }
    if combined_impact.is_empty() {
        let _ = writeln!(md, "The aggregation of these findings allows for full control or significant data exposure on the target asset.");
    } else {
        let _ = writeln!(md, "{}", combined_impact);
    }
    let _ = writeln!(md);

    let _ = writeln!(md, "## 4. Full Chain Walkthrough");
    for (i, f) in findings.iter().enumerate() {
        let _ = writeln!(md, "### Phase {}: {}", i+1, f.core.title);
        let _ = writeln!(md, "{}", f.core.description);
        if let Some(ai) = &f.enrichment.ai_analysis {
            let _ = writeln!(md, "\n**Tactical Path**: {}", ai.exploit_path);
        }
        let _ = writeln!(md);
    }

    let _ = writeln!(md, "## 5. Remediation");
    let _ = writeln!(md, "It is recommended to address all findings in this chain, starting with the root cause (Phase 1), as fixing downstream vulnerabilities may not prevent the initial access or information leak.");

    Some(BugBountyReport { filename, content: md })
}

fn severity_label(s: &Severity) -> &'static str {
    match s {
        Severity::Critical => "Critical (P1)",
        Severity::High     => "High (P2)",
        Severity::Medium   => "Medium (P3)",
        Severity::Low      => "Low (P4)",
        Severity::Info     => "Informational (P5)",
    }
}

fn default_impact(s: &Severity) -> &'static str {
    match s {
        Severity::Critical => "An attacker could fully compromise the affected system or data, leading to complete loss of confidentiality, integrity, or availability.",
        Severity::High     => "An attacker could gain significant unauthorized access or cause substantial damage to the affected system or its users.",
        Severity::Medium   => "An attacker could obtain sensitive information or perform actions that partially compromise the security of the affected system.",
        _                  => "Limited security impact. No immediate risk to users or data.",
    }
}

fn default_remediation(_severity: &Severity, category: &Category) -> &'static str {
    match category {
        Category::Vulnerability => "Implement robust input validation and output encoding. Ensure all software components are patched to the latest version.",
        Category::Misconfiguration => "Review the configuration against security benchmarks (e.g., CIS). Disable unnecessary services and implement the principle of least privilege.",
        Category::CredentialLeak => "Revoke the leaked credentials immediately and rotate them. Enable MFA and investigate if the credentials were used for unauthorized access.",
        Category::Idor => "Implement proper access control checks at the object level. Ensure users can only access resources they are authorized to view.",
        Category::FileUploadVulnerability => "Restrict allowed file types, implement strict filename validation, and store uploaded files in a non-executable directory.",
        _ => "Investigate the finding and apply necessary security controls or patches according to organizational policy."
    }
}

// --- Phase 1: Repro-Proof Generator Enhancements ---

struct HttpEvidence<'a> {
    raw_request: Option<&'a str>,
    raw_response: Option<&'a str>,
}

fn http_evidence_view(finding: &Finding) -> HttpEvidence<'_> {
    let data = finding.evidence.primary.as_ref().map(|e| &e.data);
    HttpEvidence {
        raw_request: data.and_then(|d| d.get("raw_request")).and_then(|v| v.as_str()),
        raw_response: data.and_then(|d| d.get("raw_response")).and_then(|v| v.as_str()),
    }
}

/// Parses a raw HTTP request and returns a formatted curl command.
fn build_curl_from_raw(raw: &str, default_host: &str) -> Option<String> {
    let mut lines = raw.lines();
    let first_line = lines.next()?;
    let mut parts = first_line.split_whitespace();
    
    let method = parts.next()?;
    let path = parts.next()?;
    
    let mut headers = Vec::new();
    let mut host = default_host.to_string();
    let mut body = String::new();
    let mut reading_body = false;

    for line in lines {
        if reading_body {
            body.push_str(line);
            body.push('\n');
            continue;
        }

        if line.is_empty() {
            reading_body = true;
            continue;
        }

        if let Some((key, value)) = line.split_once(':') {
            let key = key.trim();
            let value = value.trim();
            if key.eq_ignore_ascii_case("Host") {
                host = value.to_string();
            }
            // Skip common auto-generated headers that curl adds anyway or might cause issues
            if !key.eq_ignore_ascii_case("Content-Length") {
                headers.push((key.to_string(), value.to_string()));
            }
        }
    }

    let url = if path.starts_with("http") {
        path.to_string()
    } else {
        format!("https://{}{}", host, path)
    };

    let mut curl = format!("curl -i -s -k -X {}", method);
    
    for (k, v) in headers {
        let _ = write!(curl, " \\\n  -H \"{}: {}\"", k, v.replace('\"', "\\\""));
    }

    if !body.trim().is_empty() {
        let escaped_body = body.trim().replace('\'', "'\\''");
        let _ = write!(curl, " \\\n  --data-raw '{}'", escaped_body);
    }

    let escaped_url = url.replace('\'', "'\\''");
    let _ = write!(curl, " \\\n  '{}'", escaped_url);

    Some(curl)
}

#[cfg(test)]
mod tests {
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
}
