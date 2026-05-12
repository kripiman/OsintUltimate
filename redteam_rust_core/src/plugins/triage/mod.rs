pub mod similarity_engine;
pub mod dedup_rules;

use crate::models::Finding;
use dedup_rules::TriageEngine;

/// Main entry point for the Triage and De-duplication module.
/// This processes raw findings from scanners and groups duplicates.
pub async fn process(findings: Vec<Finding>) -> Vec<Finding> {
    let mut engine = TriageEngine::new();
    engine.process(findings).await
}
