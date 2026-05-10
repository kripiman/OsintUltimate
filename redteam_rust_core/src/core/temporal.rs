use crate::models::TargetHost;
use sqlx::PgPool;
use anyhow::Result;
use tracing::info;
use std::sync::Arc;

/// Compares current scan findings against historical findings for the same target host.
/// Modifies the `is_new` flag on `finding.enrichment` if the finding is discovered for the first time.
pub async fn diff_target(pool: &PgPool, target: &mut TargetHost) -> Result<()> {
    // If the target has no scan_id (e.g. running in purely ephemeral mode), skip diffing.
    let current_scan_id = match target.scan_id {
        Some(id) => id,
        None => return Ok(()),
    };

    if target.findings.is_empty() {
        return Ok(());
    }

    // Query historical finding IDs for this host, explicitly excluding the current scan
    // to avoid "everything is old" bugs.
    let historical_finding_ids: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT f.id 
        FROM findings f 
        JOIN targets t ON f.target_id = t.id 
        WHERE t.host = $1 AND t.scan_id < $2
        "#
    )
    .bind(&target.host)
    .bind(current_scan_id)
    .fetch_all(pool)
    .await?;

    let mut new_count = 0;
    
    // We must clone the Vec to mutate the findings because Arc<Vec> is immutable.
    let mut modified_findings = (*target.findings).clone();

    for finding in modified_findings.iter_mut() {
        if !historical_finding_ids.contains(&finding.core.id) {
            finding.enrichment.is_new = true;
            new_count += 1;
        }
    }

    // Commit the mutations back into the Arc
    target.findings = Arc::new(modified_findings);

    if new_count > 0 {
        info!("🕒 TEMPORAL DIFF: Discovered {} NEW findings for {}", new_count, target.host);
    }

    Ok(())
}
