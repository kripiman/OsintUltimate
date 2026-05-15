use std::sync::Arc;
use tracing::info;
use crate::models::TargetHost;

pub async fn enrich_target_findings_static(target: &mut TargetHost) {
    let manager = match crate::utils::cve_cache::CveCacheManager::global() {
        Some(m) => m,
        None => return,
    };

    let re = regex::Regex::new(r"CVE-\d{4}-\d{4,}").unwrap();
    let findings_mut = Arc::make_mut(&mut target.findings);

    for finding in findings_mut.iter_mut() {
        let cve_id = if let Some(cap) = re.captures(&finding.id) {
            Some(cap[0].to_uppercase())
        } else { re.captures(&finding.title).map(|cap| cap[0].to_uppercase()) };

        if let Some(id) = cve_id {
            if let Ok(Some(meta)) = manager.get_or_fetch_cve(&id).await {
                info!("✨ V14.2 ENRICH: Enriched finding {} with cached metadata for {}", finding.core.id, id);
                if finding.core.tactical_path.is_none() {
                    finding.core.tactical_path = meta.tactical_path;
                }
                if let Some(score) = meta.cvss_score {
                    finding.enrichment.cvss_score = Some(score);
                }
                for r in meta.references {
                    if !finding.enrichment.references.contains(&r) {
                        finding.enrichment.references.push(r);
                    }
                }
            }
        }
    }
}
