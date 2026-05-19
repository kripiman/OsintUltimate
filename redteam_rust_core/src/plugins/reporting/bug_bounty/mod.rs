mod score;
mod helpers;

#[cfg(test)]
mod tests;

use crate::models::{Finding, Severity, TargetHost};
use std::fmt::Write;

pub(crate) use score::triage_readiness_score;

use helpers::{
    severity_label, default_impact, default_remediation,
    http_evidence_view, build_curl_from_raw,
};

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
