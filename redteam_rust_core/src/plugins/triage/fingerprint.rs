use crate::models::Finding;

/// Constructs a deterministic TLSH fingerprint for a finding.
///
/// C8 FIX: Includes `core.title` (high signal — distinguishes same vuln type on different endpoints).
/// C2 FIX: Evidence JSON is canonicalized (sorted keys, proper quoting) for determinism.
/// D5 FIX: Uses `serde_json::to_string` for all JSON primitives to ensure correct quoting.
pub fn build_fingerprint(finding: &Finding) -> String {
    let mut parts = Vec::with_capacity(3);

    // C8: title carries vuln name + target endpoint — high dedup signal
    parts.push(finding.core.title.clone());
    parts.push(finding.core.description.clone());

    if let Some(ref ev) = finding.evidence.primary {
        parts.push(canonicalize_json(&ev.data));
    }

    parts.join("|")
}

/// Canonical JSON serialization with deterministic key ordering.
///
/// C2 FIX: Keys sorted explicitly (IndexMap does not guarantee order).
/// D5 FIX: All keys and primitive values serialized via `serde_json::to_string`
///         to ensure correct quoting (prevents string collisions).
pub(crate) fn canonicalize_json(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::Object(map) => {
            let mut sorted: Vec<_> = map.iter().collect();
            sorted.sort_by_key(|(k, _)| k.as_str());
            let inner = sorted
                .iter()
                .map(|(k, v)| {
                    // D5: Use serde_json for key serialization (adds quotes around string keys)
                    let key_json = serde_json::to_string(k.as_str()).unwrap_or_default();
                    format!("{}:{}", key_json, canonicalize_json(v))
                })
                .collect::<Vec<_>>()
                .join(",");
            format!("{{{}}}", inner)
        }
        serde_json::Value::Array(arr) => {
            let inner = arr.iter().map(canonicalize_json).collect::<Vec<_>>().join(",");
            format!("[{}]", inner)
        }
        // D5: All primitives via serde_json — strings get quotes, numbers don't, booleans correct
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_json_sorts_keys() {
        let json: serde_json::Value = serde_json::json!({
            "z_key": "last",
            "a_key": "first",
            "m_key": "middle"
        });
        let result = canonicalize_json(&json);
        // Keys must appear in sorted order
        let a_pos = result.find("a_key").unwrap();
        let m_pos = result.find("m_key").unwrap();
        let z_pos = result.find("z_key").unwrap();
        assert!(a_pos < m_pos, "a_key should come before m_key");
        assert!(m_pos < z_pos, "m_key should come before z_key");
    }

    #[test]
    fn canonical_json_string_values_are_quoted() {
        let json: serde_json::Value = serde_json::json!({"key": "value"});
        let result = canonicalize_json(&json);
        // D5: string values must be quoted
        assert!(result.contains("\"value\""), "String values must be quoted, got: {}", result);
        // D5: string keys must be quoted
        assert!(result.contains("\"key\""), "String keys must be quoted, got: {}", result);
    }

    #[test]
    fn canonical_json_numeric_no_quotes() {
        let json: serde_json::Value = serde_json::json!({"port": 8080});
        let result = canonicalize_json(&json);
        // Numbers should NOT be quoted
        assert!(result.contains("8080"), "Numeric values should not be quoted, got: {}", result);
        assert!(!result.contains("\"8080\""), "Numeric values should not be quoted");
    }

    #[test]
    fn canonical_json_deterministic() {
        // Same JSON object built two ways must produce same canonical string
        let json1: serde_json::Value = serde_json::json!({"b": 2, "a": 1});
        let json2: serde_json::Value = serde_json::json!({"a": 1, "b": 2});
        assert_eq!(canonicalize_json(&json1), canonicalize_json(&json2));
    }

    #[test]
    fn build_fingerprint_includes_title() {
        use crate::models::{Finding, Category, Severity};
        let finding = Finding::new(
            "test-id",
            Category::Vulnerability,
            Severity::High,
            "This is the description of the finding.",
            serde_json::json!({}),
        );
        let fp = build_fingerprint(&finding);
        // Title should be present in fingerprint
        assert!(fp.contains(&finding.core.title), "Fingerprint must include title");
        assert!(fp.contains(&finding.core.description), "Fingerprint must include description");
    }

    #[test]
    fn build_fingerprint_is_deterministic() {
        use crate::models::{Finding, Category, Severity};
        let finding = Finding::new(
            "test-id-2",
            Category::Misconfiguration,
            Severity::Medium,
            "Open S3 bucket detected at s3://target-bucket.",
            serde_json::json!({"bucket": "target-bucket", "region": "us-east-1"}),
        );
        let fp1 = build_fingerprint(&finding);
        let fp2 = build_fingerprint(&finding);
        assert_eq!(fp1, fp2, "Fingerprint must be deterministic");
    }
}
