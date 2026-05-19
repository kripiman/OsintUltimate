use super::{bk_tree::BkTree, fingerprint::build_fingerprint, similarity_engine};
use crate::models::{Finding, Category, Severity};
use std::collections::HashMap;
use tracing::{debug, info, warn};

const SIMILARITY_THRESHOLD: u32 = 30;

/// Shard key: groups findings by vulnerability class for efficient BK-Tree partitioning.
///
/// C3: Using (Category, Severity) creates ~90 shards max (18 categories × 5 severities).
/// Hot-shard detection: a warn! fires at runtime if any shard exceeds 50% of total findings.
#[derive(Hash, Eq, PartialEq, Clone, Debug)]
struct ShardKey {
    category: Category,
    severity: Severity,
}

/// Fuzzy deduplication engine using TLSH + BK-Tree, sharded by (Category, Severity).
///
/// LIFETIME INVARIANT (C1 — Plan A):
///   This engine is per-target, per-scan. It is created fresh for each `process()` call.
///   It does NOT accumulate state across different targets or scan sessions.
///
///   Cross-session exact dedup is handled by `utils::deduplication::DeduplicationEngine`
///   (V14.2, SHA-256 + Postgres-backed). These two systems have complementary, non-overlapping
///   responsibilities:
///     - V14.2: exact dedup, cross-scan, persistent
///     - TriageEngine: fuzzy dedup, intra-batch, ephemeral
pub struct TriageEngine {
    shards: HashMap<ShardKey, BkTree>,
}

impl TriageEngine {
    pub fn new() -> Self {
        Self {
            shards: HashMap::new(),
        }
    }

    pub async fn process(&mut self, findings: Vec<Finding>) -> Vec<Finding> {
        let mut unique: Vec<Finding> = Vec::new();
        let mut skipped = 0usize;
        let mut unindexed = 0usize;

        // C3: Track shard distribution to detect hot-shard skew
        let mut shard_counts: HashMap<ShardKey, usize> = HashMap::new();

        for mut finding in findings {
            let key = ShardKey {
                category: finding.core.category.clone(),
                severity: finding.core.severity.clone(),
            };
            *shard_counts.entry(key.clone()).or_insert(0) += 1;

            // C2 + C8 + D5: Deterministic canonical fingerprint (title + description + JSON)
            let fingerprint = build_fingerprint(&finding);

            if let Some(hash) = similarity_engine::compute_tlsh(&fingerprint) {
                finding.enrichment.similarity_hash = Some(hash.clone());

                // C6: No &dyn Fn — BkTree calls calculate_distance directly (zero vtable overhead)
                let shard = self.shards.entry(key).or_default();

                // C5: find_any_within short-circuits on first hit
                // A7: find FIRST, then decide, then insert (borrow separation)
                if shard.find_any_within(&hash, SIMILARITY_THRESHOLD) {
                    debug!("TRIAGE: Duplicate merged via BK-Tree (hash: {}...)", &hash[..hash.len().min(8)]);
                    skipped += 1;
                    continue;
                }

                // D3: insert returns false on distance failure — treat as unique but unindexed
                if !shard.insert(hash, unique.len()) {
                    warn!("TRIAGE: Finding unindexed (BK-Tree insert failed) — treated as unique.");
                    unindexed += 1;
                }
            } else {
                // Fallback for inputs < 50 bytes: exact match on title within same category
                let is_exact_dup = unique.iter().any(|ex| {
                    ex.core.category == finding.core.category
                        && ex.core.title == finding.core.title
                });
                if is_exact_dup {
                    skipped += 1;
                    continue;
                }
            }

            unique.push(finding);
        }

        // C3: Hot-shard detection — warn if any shard dominates
        let total = shard_counts.values().sum::<usize>();
        if total > 0 {
            if let Some((hot_key, hot_count)) = shard_counts.iter().max_by_key(|(_, &c)| c) {
                let pct = *hot_count as f64 / total as f64 * 100.0;
                if pct > 50.0 {
                    warn!(
                        "⚠️ TRIAGE: Hot shard detected — {:?} holds {:.0}% of findings ({}/{}). \
                         Consider adding plugin_prefix as sub-shard dimension.",
                        hot_key, pct, hot_count, total
                    );
                }
            }
        }

        if skipped > 0 || unindexed > 0 {
            info!(
                "🛡️ TRIAGE v3: {} duplicates merged, {} unindexed. {} active shards. {} unique findings remain.",
                skipped,
                unindexed,
                self.shards.len(),
                unique.len()
            );
        }

        unique
    }
}

impl Default for TriageEngine {
    fn default() -> Self {
        Self::new()
    }
}
