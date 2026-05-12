use crate::models::Finding;
use super::similarity_engine;
use tracing::{debug, info};

const SIMILARITY_THRESHOLD: u32 = 30; // TLSH distance < 30 indicates high similarity (>85%)

pub struct TriageEngine;

impl TriageEngine {
    pub fn new() -> Self {
        Self
    }

    /// Main processing loop for deduplication.
    /// 
    /// NOTE (Complexity): Current implementation is O(n^2) due to nested similarity comparison.
    /// This is acceptable for findings counts < 1000. For larger scales, consider KD-Tree or BK-Tree.
    pub async fn process(&mut self, findings: Vec<Finding>) -> Vec<Finding> {
        let mut unique_findings: Vec<Finding> = Vec::new();
        let mut skipped_count = 0;

        for mut finding in findings {
            // Compute TLSH based on description + evidence data to form a robust fingerprint
            let mut input_data = finding.core.description.clone();
            if let Some(ref ev) = finding.evidence.evidence {
                if let Ok(json_str) = serde_json::to_string(&ev.data) {
                    input_data.push_str(&json_str);
                }
            }

            if let Some(hash) = similarity_engine::compute_tlsh(&input_data) {
                finding.enrichment.similarity_hash = Some(hash.clone());
                
                // Compare with existing unique findings
                let mut is_duplicate = false;
                for existing in &mut unique_findings {
                    // [Constraint]: Only compare findings of the same root vulnerability type (core.id).
                    // This prevents cross-vulnerability merging but might miss identical flaws reported by tools with different IDs.
                    if finding.core.id == existing.core.id { 
                        if let Some(ref existing_hash) = existing.enrichment.similarity_hash {
                            if let Some(distance) = similarity_engine::calculate_distance(&hash, existing_hash) {
                                if distance < SIMILARITY_THRESHOLD {
                                    debug!("Triage: Merged duplicate {} (distance {})", finding.core.id, distance);
                                    is_duplicate = true;
                                    break;
                                }
                            }
                        }
                    }
                }

                if is_duplicate {
                    skipped_count += 1;
                    continue; // Skip adding this to the unique list
                }
            } else {
                // Fallback for inputs < 50 bytes: exact matching on ID and Title
                let mut is_duplicate = false;
                for existing in &mut unique_findings {
                    if finding.core.id == existing.core.id && finding.core.title == existing.core.title {
                        is_duplicate = true;
                        break;
                    }
                }
                if is_duplicate {
                    skipped_count += 1;
                    continue;
                }
            }

            // It's a new, unique finding
            unique_findings.push(finding);
        }

        if skipped_count > 0 {
            info!("🛡️ TRIAGE ENGINE: Consolidated {} redundant findings via fuzzy TLSH clustering", skipped_count);
        }

        unique_findings
    }
}
