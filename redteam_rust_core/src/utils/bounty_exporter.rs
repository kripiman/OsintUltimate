use crate::models::{Finding, ReportPlatform, Severity};

pub struct BountyExporter;

impl BountyExporter {
    pub fn generate(findings: &[&Finding], platform: &ReportPlatform) -> String {
        let eligible: Vec<&Finding> = findings
            .iter()
            .copied()
            .filter(|f| matches!(f.core.severity, Severity::High | Severity::Critical))
            .collect();

        if eligible.is_empty() {
            return format!(
                "# {} — No Eligible Findings\n\nNo High/Critical findings available for export.",
                platform.display_name()
            );
        }

        match platform {
            ReportPlatform::HackerOne => Self::generate_h1(&eligible),
            ReportPlatform::BugCrowd => Self::generate_bugcrowd(&eligible),
            ReportPlatform::Intigriti => Self::generate_intigriti(&eligible),
        }
    }

    fn compress_evidence(finding: &Finding) -> String {
        let raw = finding.evidence.primary.as_ref()
            .map(|e| serde_json::to_string_pretty(&e.data).unwrap_or_default())
            .unwrap_or_default();

        const MAX: usize = 4096; 
        if raw.len() > MAX {
            format!("{}\n... [+{} bytes truncated]", &raw[..MAX], raw.len() - MAX)
        } else {
            raw
        }
    }

    fn poc_steps(finding: &Finding) -> String {
        if let Some(ai) = &finding.enrichment.ai_analysis {
            if !ai.exploit_path.is_empty() {
                return ai.exploit_path.clone();
            }
        }
        if let Some(url) = finding.evidence.primary.as_ref().and_then(|e| e.data.get("url")).and_then(|v| v.as_str()) {
            return format!("1. Navigate to: `{}`\n2. Observe the response headers and body for vulnerability indicators.", url);
        }
        "1. Capture the raw HTTP request from the 'Proof of Concept' section below.\n2. Replay the request in Burp Suite Repeater.\n3. Verify the impact in the response.".to_string()
    }

    fn impact(finding: &Finding) -> String {
        if let Some(ai) = &finding.enrichment.ai_analysis {
            if !ai.impact.is_empty() {
                return ai.impact.clone();
            }
        }
        format!("An attacker can leverage this {:?} severity issue in the {:?} category to compromise the target application's security posture.", finding.core.severity, finding.core.category)
    }

    fn attack_scenario(finding: &Finding) -> String {
        if let Some(ai) = &finding.enrichment.ai_analysis {
            if !ai.stealth_notes.is_empty() {
                return ai.stealth_notes.clone(); 
            }
        }
        "1. Attacker identifies the vulnerable endpoint.\n2. Attacker crafts a specific payload based on the observed behavior.\n3. Result: Unauthorized action or data exposure is achieved.".to_string()
    }

    fn recommendation(finding: &Finding) -> String {
        match finding.core.category {
            _ if finding.core.title.to_lowercase().contains("xss") => 
                "Implement strict output encoding and use a Content Security Policy (CSP). Sanitize all user-controlled input using a vetted library.",
            _ if finding.core.title.to_lowercase().contains("idor") || finding.core.title.to_lowercase().contains("bola") => 
                "Implement object-level authorization checks. Ensure the authenticated user has rights to access the requested resource ID.",
            _ if finding.core.title.to_lowercase().contains("ssrf") => 
                "Implement an allow-list for outgoing requests. Do not allow the application to make requests to internal IP ranges (127.0.0.1, 169.254.169.254, etc.).",
            _ => "Implement proper input validation and follow the principle of least privilege for application components."
        }.to_string()
    }

    fn generate_common_blocks(f: &Finding) -> String {
        let mut out = String::new();
        
        out.push_str("## Summary\n");
        if let Some(ai) = &f.enrichment.ai_analysis {
            out.push_str(&ai.summary);
        } else {
            out.push_str(&f.core.description);
        }
        out.push_str("\n\n");

        out.push_str("## Vulnerability Details\n");
        out.push_str(&format!("- **Type:** {:?}\n", f.core.category));
        if let Some(url) = f.evidence.primary.as_ref().and_then(|e| e.data.get("url")).and_then(|v| v.as_str()) {
            out.push_str(&format!("- **Affected Endpoint:** {}\n", url));
        }
        if !f.enrichment.cwe.is_empty() {
            out.push_str(&format!("- **CWE:** {}\n", f.enrichment.cwe.join(", ")));
        }
        // V14.7: CVSS data in submission path (previously only in draft path)
        if let Some(score) = f.enrichment.cvss_score {
            out.push_str(&format!("- **CVSS Score:** {:.1}\n", score));
        }
        if let Some(ref vector) = f.enrichment.cvss_vector {
            out.push_str(&format!("- **CVSS Vector:** `{}`\n", vector));
        }
        out.push('\n');

        out.push_str("## Steps to Reproduce\n");
        out.push_str(&Self::poc_steps(f));
        out.push_str("\n\n");

        out.push_str("## Proof of Concept\n");
        out.push_str("Below is the raw evidence captured during validation:\n\n");
        out.push_str("```json\n");
        out.push_str(&Self::compress_evidence(f));
        out.push_str("\n```\n\n");

        out.push_str("## Impact\n");
        out.push_str(&Self::impact(f));
        out.push_str("\n\n");

        out.push_str("## Attack Scenario\n");
        out.push_str(&Self::attack_scenario(f));
        out.push_str("\n\n");

        out.push_str("## Recommendation\n");
        out.push_str(&Self::recommendation(f));
        out.push_str("\n\n");

        if !f.enrichment.references.is_empty() || !f.enrichment.cwe.is_empty() {
            out.push_str("## References\n");
            for r in &f.enrichment.references {
                out.push_str(&format!("- {}\n", r));
            }
            for c in &f.enrichment.cwe {
                out.push_str(&format!("- https://cwe.mitre.org/data/definitions/{}.html\n", c.replace("CWE-", "")));
            }
            out.push('\n');
        }

        out
    }

    fn generate_h1(findings: &[&Finding]) -> String {
        let mut out = String::from("# Bounty Report — HackerOne\n\n");
        for f in findings {
            out.push_str(&format!("# {}\n\n", f.core.title));
            out.push_str(&Self::generate_common_blocks(f));
            out.push_str("\n---\n\n");
        }
        out
    }

    fn generate_bugcrowd(findings: &[&Finding]) -> String {
        let mut out = String::from("# Bounty Report — Bugcrowd\n\n");
        for f in findings {
            out.push_str(&format!("# {}\n\n", f.core.title));
            out.push_str(&Self::generate_common_blocks(f));
            out.push_str("\n---\n\n");
        }
        out
    }

    fn generate_intigriti(findings: &[&Finding]) -> String {
        let mut out = String::from("# Bounty Report — Intigriti\n\n");
        for f in findings {
            out.push_str(&format!("# {}\n\n", f.core.title));
            out.push_str(&Self::generate_common_blocks(f));
            out.push_str("\n---\n\n");
        }
        out
    }
}
