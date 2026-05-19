use crate::models::{Finding, Severity, AIAnalysis, Category};

pub fn enrich_findings(all_findings: &mut [Finding]) {
    for f in all_findings.iter_mut() {
        f.enrich_with_cvss();
        if f.enrichment.ai_analysis.is_none() {
             if let Some(poc) = crate::utils::poc_generator::PocGenerator::generate_suggested_poc(f) {
                 f.enrichment.ai_analysis = Some(AIAnalysis {
                     summary: "Automated Mimikri enrichment".into(),
                     impact: "Potential impact detected by scanner.".into(),
                     stealth_notes: "Follow stealth policy for exploitation.".into(),
                     risk_score: match f.core.severity {
                         Severity::Critical => 90,
                         Severity::High => 70,
                         Severity::Medium => 50,
                         _ => 20,
                     },
                     confidence: 0.7,
                     mitre_attack: None,
                     exploit_path: poc,
                     model: "Mimikri-Engine".into(),
                     poc: None,
                     usage: Default::default(),
                 });
             }
        }
    }
}

pub fn suggest_blackarch_tools(
    findings: &[Finding],
    ba_bridge: &crate::core::blackarch::BlackArchBridge,
) -> Vec<String> {
    let mut suggestions = Vec::new();
    for finding in findings {
        if finding.severity == Severity::High || finding.severity == Severity::Critical {
            let capability = match finding.category {
                Category::Vulnerability => Some(crate::plugins::Capability::VulnerabilityScanning),
                Category::NetworkPort => Some(crate::plugins::Capability::ServiceDiscovery),
                _ => None,
            };

            if let Some(cap) = capability {
                let suggested = ba_bridge.suggest_tools_for_capability(cap);
                for tool in suggested {
                    if !suggestions.contains(&tool.name) {
                        suggestions.push(tool.name.clone());
                    }
                }
            }
        }
    }
    suggestions
}
