use crate::models::Finding;

/// V14.7: 0-100 Triage Readiness Score. Gates auto-submit (≥70) vs manual review vs do-not-submit.
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
    if !finding.enrichment.references.is_empty() { score += 10; }

    score.min(100) as u8
}
