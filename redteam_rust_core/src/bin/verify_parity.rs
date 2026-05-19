use redteam_rust_core::models::Finding;
use std::fs;
use anyhow::Result;
use std::collections::{HashMap, HashSet};
use sha2::{Sha256, Digest};

pub struct ParityReport {
    pub l1_passed: bool,
    pub l2_passed: bool,
    pub l3_passed: bool,
}

pub fn verify_parity(baseline_path: &str, current_path: &str) -> Result<ParityReport> {
    let baseline_raw = fs::read_to_string(baseline_path)?;
    let current_raw = fs::read_to_string(current_path)?;
    
    let mut baseline: Vec<Finding> = serde_json::from_str(&baseline_raw)?;
    let mut current: Vec<Finding> = serde_json::from_str(&current_raw)?;
    
    // Normalize: Ignore timestamps for comparison
    let default_time = chrono::DateTime::default();
    for f in &mut baseline { f.core.timestamps = default_time; }
    for f in &mut current { f.core.timestamps = default_time; }

    // L1: Quantitative (< 2% delta per category)
    let l1_passed = check_l1(&baseline, &current);
    
    // L2: Qualitative (Identity intersection via SHA256)
    let l2_passed = check_l2(&baseline, &current);
    
    // L3: Structural (Whitelist of TypeId keys - currently using extra_data keys as proxy)
    let l3_passed = check_l3(&baseline, &current);
    
    Ok(ParityReport { l1_passed, l2_passed, l3_passed })
}

fn compute_id(f: &Finding) -> String {
    let mut hasher = Sha256::new();
    let plugin = f.core.source_plugin.as_deref().unwrap_or("unknown");
    let target = f.core.target.as_deref().unwrap_or("unknown");
    let identity = format!("{}|{}|{}", plugin, target, f.core.title);
    hasher.update(identity.as_bytes());
    hex::encode(hasher.finalize())
}

fn check_l1(baseline: &[Finding], current: &[Finding]) -> bool {
    let mut b_counts = HashMap::new();
    let mut c_counts = HashMap::new();
    
    for f in baseline { *b_counts.entry(format!("{:?}", f.core.category)).or_insert(0) += 1; }
    for f in current { *c_counts.entry(format!("{:?}", f.core.category)).or_insert(0) += 1; }
    
    for (cat, b_count) in b_counts {
        let c_count = *c_counts.get(&cat).unwrap_or(&0);
        let delta = (b_count as f32 - c_count as f32).abs();
        if delta / (b_count as f32) > 0.02 {
            println!("L1 Fail: Category {:?} delta too high (B:{} C:{})", cat, b_count, c_count);
            return false;
        }
    }
    true
}

fn check_l2(baseline: &[Finding], current: &[Finding]) -> bool {
    let b_ids: HashSet<String> = baseline.iter().map(compute_id).collect();
    let c_ids: HashSet<String> = current.iter().map(compute_id).collect();
    
    if b_ids != c_ids {
        let missing: Vec<_> = b_ids.difference(&c_ids).collect();
        let extra: Vec<_> = c_ids.difference(&b_ids).collect();
        println!("L2 Fail: IDs do not match.\nMissing: {:?}\nExtra: {:?}", missing, extra);
        return false;
    }
    true
}

fn check_l3(baseline: &[Finding], current: &[Finding]) -> bool {
    // Structural check: Compare the "shape" of findings
    for (b, c) in baseline.iter().zip(current.iter()) {
        // 1. Target presence & value equality match
        match (&b.core.target, &c.core.target) {
            (None, None) => {} // OK Phase 0 PLUGIN_ERROR
            (Some(bt), Some(ct)) if bt == ct => {} // String value equality
            (a, b_) => {
                println!("L3 Fail: target divergence baseline={a:?} current={b_:?}");
                return false;
            }
        }
        
        // 2. Evidence shape
        if b.evidence.primary.is_some() != c.evidence.primary.is_some() {
            println!("L3 Fail: Evidence presence mismatch for {}", b.core.title);
            return false;
        }

        // 3. AI Enrichment shape
        if b.enrichment.ai_analysis.is_some() != c.enrichment.ai_analysis.is_some() {
            println!("L3 Fail: AI analysis presence mismatch for {}", b.core.title);
            return false;
        }

        // 4. Source Plugin attribution
        if b.core.source_plugin != c.core.source_plugin {
            println!("L3 Fail: Source plugin mismatch for {}", b.core.title);
            return false;
        }
    }
    true
}

fn main() -> Result<()> {
    let report = verify_parity("tests/baselines/golden_baseline.json", "target/current_scan.json")?;
    if report.l1_passed && report.l2_passed && report.l3_passed {
        println!("✅ Parity Verified!");
        Ok(())
    } else {
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_dummy_finding(target: Option<&str>) -> Finding {
        let target_json = match target {
            Some(t) => format!("\"{}\"", t),
            None => "null".to_string(),
        };
        let raw = format!(
            r#"{{
              "id": "PLUGIN_ERROR",
              "category": "misconfiguration",
              "severity": "info",
              "title": "Plugin NucleiScanner failed",
              "description": "Plugin NucleiScanner failed",
              "timestamps": "2026-05-15T15:15:10.450465952Z",
              "version": 0,
              "source_plugin": null,
              "scope_id": "",
              "reactive_depth": 0,
              "target": {},
              "evidence": {{
                "error": "DNS Pinning Violation",
                "confidence": 0.5,
                "verified": false
              }},
              "enrichment": {{
                "cvss_version": "4.0"
              }},
              "context": {{
                "iteration": 0,
                "validation": {{
                  "status": "unverified",
                  "confidence_score": 0.0,
                  "judge_notes": "",
                  "negative_control_passed": false,
                  "proof_of_execution": null,
                  "validated_at": null
                }}
              }}
            }}"#,
            target_json
        );
        serde_json::from_str(&raw).unwrap()
    }

    #[test]
    fn test_l3_target_value_match_accepted() {
        // Case 1: Both None
        let b1 = vec![create_dummy_finding(None)];
        let c1 = vec![create_dummy_finding(None)];
        assert!(check_l3(&b1, &c1));

        // Case 2: Both Some and equal
        let b2 = vec![create_dummy_finding(Some("127.0.0.1"))];
        let c2 = vec![create_dummy_finding(Some("127.0.0.1"))];
        assert!(check_l3(&b2, &c2));
    }

    #[test]
    fn test_l3_target_value_mismatch_detected() {
        // Case 1: None vs Some
        let b1 = vec![create_dummy_finding(None)];
        let c1 = vec![create_dummy_finding(Some("127.0.0.1"))];
        assert!(!check_l3(&b1, &c1));

        // Case 2: Some vs None
        let b2 = vec![create_dummy_finding(Some("127.0.0.1"))];
        let c2 = vec![create_dummy_finding(None)];
        assert!(!check_l3(&b2, &c2));

        // Case 3: Some vs Some but different
        let b3 = vec![create_dummy_finding(Some("127.0.0.1"))];
        let c3 = vec![create_dummy_finding(Some("10.0.0.1"))];
        assert!(!check_l3(&b3, &c3));
    }
}
