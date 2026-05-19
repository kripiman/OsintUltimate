use tlsh_fixed::{TlshBuilder, BucketKind, ChecksumKind, Version};
use crate::models::Finding;
use crate::plugins::triage::bk_tree::{BkTree, SimHashBkTree};

pub struct SimilarityEngine {
    tlsh_tree: BkTree,
    simhash_tree: SimHashBkTree,
    #[allow(dead_code)]
    threshold_tlsh: u32,
    threshold_simhash: u32,
}

impl Default for SimilarityEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl SimilarityEngine {
    pub fn new() -> Self {
        Self {
            tlsh_tree: BkTree::new(),
            simhash_tree: SimHashBkTree::new(),
            threshold_tlsh: 30,
            threshold_simhash: 5, // Sprint 3: Tuned for shingling (Hamming distance)
        }
    }

    /// Deduplicates a list of findings, merging evidence for near-duplicates.
    /// V15.1: Uses 64-bit SimHash with 3-char shingling.
    pub fn dedup_findings(&mut self, findings: Vec<Finding>) -> Vec<Finding> {
        let mut results: Vec<Finding> = Vec::new();

        for finding in findings {
            let text = format!("{} {}", finding.core.title, finding.core.description);
            let shash = compute_simhash(&text);

            if let Some(original_idx) = self.simhash_tree.find_similar_within(shash, self.threshold_simhash) {
                // Near-duplicate found! Merge evidence.
                let original = &mut results[original_idx];
                original.enrichment.merged_from.push(finding.core.id.clone());
                
                // Merge evidence data (preserving original values on conflict)
                if let (Some(orig_ev), Some(new_ev)) = (&mut original.evidence.primary, &finding.evidence.primary) {
                    if let (Some(orig_obj), Some(new_obj)) = (orig_ev.data.as_object_mut(), new_ev.data.as_object()) {
                        for (k, v) in new_obj {
                            if !orig_obj.contains_key(k) {
                                orig_obj.insert(k.clone(), v.clone());
                            }
                        }
                    }
                }
                continue;
            }

            // New unique finding - register in SimHash tree
            self.simhash_tree.insert(shash, results.len());
            
            // Also index in TLSH if text is long enough (min 50 bytes)
            if let Some(thash) = compute_tlsh(&text) {
                self.tlsh_tree.insert(thash, results.len());
            }

            results.push(finding);
        }

        results
    }
}

/// Computes the TLSH hash of a given input string.
pub fn compute_tlsh(input: &str) -> Option<String> {
    if input.len() < 50 {
        return None;
    }
    
    let mut builder = TlshBuilder::new(BucketKind::Bucket128, ChecksumKind::OneByte, Version::Version4);
    builder.update(input.as_bytes());
    
    match builder.build() {
        Ok(tlsh) => Some(tlsh.hash()),
        Err(_) => None,
    }
}

/// Calculates the TLSH distance between two hashes.
pub fn calculate_distance(hash1: &str, hash2: &str) -> Option<u32> {
    use std::str::FromStr;
    let t1 = tlsh_fixed::Tlsh::from_str(hash1).ok()?;
    let t2 = tlsh_fixed::Tlsh::from_str(hash2).ok()?;
    Some(t1.diff(&t2, true) as u32)
}

/// Computes a 64-bit SimHash using 3-character sliding window shingling.
pub fn compute_simhash(input: &str) -> u64 {
    use siphasher::sip::SipHasher13;
    use std::hash::{Hash, Hasher};

    let mut v = [0i32; 64];
    let bytes = input.as_bytes();
    
    if bytes.len() >= 3 {
        for shingle in bytes.windows(3) {
            let mut hasher = SipHasher13::new();
            shingle.hash(&mut hasher);
            let hash = hasher.finish();
            
            for (i, item) in v.iter_mut().enumerate() {
                if (hash >> i) & 1 == 1 {
                    *item += 1;
                } else {
                    *item -= 1;
                }
            }
        }
    } else {
        let mut hasher = SipHasher13::new();
        input.hash(&mut hasher);
        let hash = hasher.finish();
        for (i, item) in v.iter_mut().enumerate() {
            if (hash >> i) & 1 == 1 { *item += 1; } else { *item -= 1; }
        }
    }
    
    let mut simhash = 0u64;
    for (i, &item) in v.iter().enumerate() {
        if item > 0 {
            simhash |= 1 << i;
        }
    }
    simhash
}

/// Calculates the Hamming distance between two SimHashes.
pub fn hamming_distance(h1: u64, h2: u64) -> u32 {
    (h1 ^ h2).count_ones()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Finding, Category, Severity};

    #[test]
    fn test_near_duplicate_merging() {
        let mut engine = SimilarityEngine::new();
        
        let f1 = Finding::new(
            "FINDING-1",
            Category::Vulnerability,
            Severity::High,
            "SQL injection in /api/v1/users param=id",
            serde_json::json!({"url": "http://target/api/v1/users?id=1"})
        );
        
        let f2 = Finding::new(
            "FINDING-2",
            Category::Vulnerability,
            Severity::High,
            "SQL injection in /api/v1/users param=id ",
            serde_json::json!({"extra": "data"})
        );

        let findings = vec![f1, f2];
        let deduped = engine.dedup_findings(findings);

        assert_eq!(deduped.len(), 1);
        assert_eq!(deduped[0].core.id, "FINDING-1");
        assert_eq!(deduped[0].enrichment.merged_from.len(), 1);
    }

    #[test]
    fn test_dissimilar_findings_not_merged() {
        let mut engine = SimilarityEngine::new();
        
        let f1 = Finding::new(
            "FINDING-1",
            Category::Vulnerability,
            Severity::High,
            "SQL injection in /api/v1/users param=id",
            serde_json::json!({})
        );
        
        let f2 = Finding::new(
            "FINDING-2",
            Category::Misconfiguration,
            Severity::Medium,
            "Exposed S3 bucket containing sensitive logs",
            serde_json::json!({})
        );

        let findings = vec![f1, f2];
        let deduped = engine.dedup_findings(findings);

        assert_eq!(deduped.len(), 2, "Dissimilar findings should NOT be merged");
    }

    #[test]
    fn test_batch_deduplication_stress() {
        let mut engine = SimilarityEngine::new();
        let mut findings = Vec::new();

        // 3 Very similar findings (should merge into 1)
        for i in 0..3 {
            findings.push(Finding::new(
                &format!("DUP-{}", i),
                Category::Vulnerability,
                Severity::High,
                "XSS vulnerability in search endpoint", // Same title/desc for batch test
                serde_json::json!({"attempt": i})
            ));
        }

        // 7 Distinct findings
        for i in 0..7 {
            findings.push(Finding::new(
                &format!("UNIQUE-{}", i),
                Category::Recon,
                Severity::Low,
                &format!("Subdomain discovered: node-{}.target.com", i),
                serde_json::json!({"node": i})
            ));
        }

        let deduped = engine.dedup_findings(findings);
        assert_eq!(deduped.len(), 8, "Expected 1 (merged) + 7 (unique) = 8 findings");
        
        let merged = deduped.iter().find(|f| f.core.id == "DUP-0").unwrap();
        assert_eq!(merged.enrichment.merged_from.len(), 2);
    }
}
