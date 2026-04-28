/// Bug Bounty report generator — produces one Markdown file per finding,
/// formatted for HackerOne / Bugcrowd triage requirements.
use crate::models::{Finding, Severity, TargetHost};
use std::fmt::Write;

pub struct BugBountyReport {
    pub filename: String,
    pub content: String,
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
    let _ = writeln!(md, "# {}", finding.core.title);
    let _ = writeln!(md);

    // Metadata table
    let _ = writeln!(md, "| Field | Value |");
    let _ = writeln!(md, "|---|---|");
    let _ = writeln!(md, "| **Severity** | {} |", severity_label(&finding.core.severity));
    if let Some(score) = finding.enrichment.cvss_score {
        let _ = writeln!(md, "| **CVSS Score** | {:.1} |", score);
    }
    let _ = writeln!(md, "| **Asset** | `{}` |", target.host);
    if let Some(ip) = &target.ip {
        let _ = writeln!(md, "| **IP** | `{}` |", ip);
    }
    let _ = writeln!(md, "| **Finding ID** | `{}` |", finding.core.id);
    if let Some(mitre) = &finding.enrichment.mitre_attack {
        let _ = writeln!(md, "| **MITRE ATT&CK** | {} |", mitre.join(", "));
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

    // Steps to reproduce
    let _ = writeln!(md, "## Steps to Reproduce");
    let _ = writeln!(md);
    
    let evidence_data = finding.evidence.evidence.as_ref();
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
    let _ = writeln!(md);

    // PoC evidence
    let _ = writeln!(md, "## Proof of Concept");
    let _ = writeln!(md);
    let _ = writeln!(md, "```");
    if let Some(e) = evidence_data {
        let _ = writeln!(md, "{}", serde_json::to_string_pretty(&e.data).unwrap_or_default());
    }
    let _ = writeln!(md, "```");
    let _ = writeln!(md);

    // Exploit Path
    let _ = writeln!(md, "## Exploit Path");
    let _ = writeln!(md);
    if let Some(ai) = &finding.enrichment.ai_analysis {
        let _ = writeln!(md, "{}", ai.exploit_path);
    } else {
        let _ = writeln!(md, "Please refer to the PoC evidence to understand the exploit step-by-step.");
    }
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
