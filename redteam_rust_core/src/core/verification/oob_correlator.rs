use crate::core::verification::interaction::{OobInteractionManager, OobInteraction};
use crate::utils::proxy::ProxyManager;
use anyhow::Result;
use serde_json::json;
use sqlx::PgPool;
use std::sync::Arc;
use tracing::{info, warn};

/// Sprint 10: OOB Correlator — polls interactsh-server for callbacks
/// and enriches existing findings with OOB hit metadata.
pub struct OobCorrelator {
    manager: OobInteractionManager,
    pool: PgPool,
}

impl OobCorrelator {
    pub fn new(proxy_manager: Arc<ProxyManager>, pool: PgPool) -> Self {
        Self {
            manager: OobInteractionManager::new(proxy_manager),
            pool,
        }
    }

    /// Block up to `timeout_secs` waiting for an OOB interaction.
    /// If a hit arrives, enrich all findings matching this oob_id.
    pub async fn correlate(&self, oob_id: &str, timeout_secs: u64) -> Result<bool> {
        info!("⏳ [OOB-Correlator] Waiting for interaction on {} (timeout {}s)", oob_id, timeout_secs);

        match self.manager.wait_for_interaction(oob_id, timeout_secs).await? {
            Some(hit) => {
                info!("🎯 [OOB-Correlator] HIT for {} — enriching findings", oob_id);
                self.enrich_findings(oob_id, &hit).await?;
                Ok(true)
            }
            None => {
                warn!("💤 [OOB-Correlator] Timeout for {} — no interaction detected", oob_id);
                Ok(false)
            }
        }
    }

    async fn enrich_findings(&self, oob_id: &str, hit: &OobInteraction) -> Result<()> {
        let enrichment = json!({
            "oob_hit": {
                "protocol": hit.protocol,
                "remote_address": hit.remote_address,
                "timestamp": hit.timestamp,
                "data": hit.data,
            }
        });

        // Runtime query (not sqlx::query! macro) — consistent with worker.rs pattern.
        // Single UPDATE is atomic per PostgreSQL ACID; wrapping in a transaction adds
        // overhead with no additional correctness benefit for this idempotent operation.
        let rows = sqlx::query(
            r#"
            UPDATE findings
            SET enrichment = enrichment || $1
            WHERE context->>'oob_correlation_id' = $2
            "#
        )
        .bind(enrichment)
        .bind(oob_id)
        .execute(&self.pool)
        .await?;

        info!("✅ [OOB-Correlator] Enriched {} findings for {}", rows.rows_affected(), oob_id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enrichment_json_structure() {
        let hit = OobInteraction {
            protocol: "dns".to_string(),
            remote_address: "1.2.3.4".to_string(),
            timestamp: "2026-05-25T12:00:00Z".to_string(),
            data: Some("A query for oob.example.com".to_string()),
        };
        let enrichment = serde_json::json!({
            "oob_hit": {
                "protocol": hit.protocol,
                "remote_address": hit.remote_address,
                "timestamp": hit.timestamp,
                "data": hit.data,
            }
        });
        assert!(enrichment.get("oob_hit").is_some());
        assert_eq!(enrichment["oob_hit"]["protocol"], "dns");
    }
}
