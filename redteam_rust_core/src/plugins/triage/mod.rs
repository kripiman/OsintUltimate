pub mod similarity_engine;
pub mod dedup_rules;
pub mod bk_tree;
pub mod fingerprint;

use crate::models::Finding;
use dedup_rules::TriageEngine;

/// Deduplicación fuzzy intra-batch via TLSH + BK-Tree sharded por (Category, Severity).
///
/// SCOPE: Per-target, per-scan. No acumula entre targets distintos.
/// Complementa V14.2 (`utils/deduplication.rs`): exact dedup cross-scan via SHA-256 + Postgres.
pub async fn process(findings: Vec<Finding>) -> Vec<Finding> {
    let mut engine = TriageEngine::new();
    engine.process(findings).await
}

#[cfg(test)]
mod tests {
    mod tlsh_metric_test;
}
