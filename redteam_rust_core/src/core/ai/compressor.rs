use crate::models::{Finding, Category, TargetHost};
use crate::plugins::PluginMetadata;
use super::types::RouteLevel;
use super::scrubber::SCRUBBER;

/// Helper to minify findings and plugins to save tokens.
pub struct ContextCompressor;

impl ContextCompressor {
    pub fn compress_finding(finding: &Finding, route_level: RouteLevel) -> serde_json::Value {
        if route_level == RouteLevel::Local || route_level == RouteLevel::Mid {
            return Self::compress_finding_dense(finding);
        }

        let mut ev = finding.evidence.primary.as_ref().map(|e| e.data.clone()).unwrap_or_else(|| serde_json::json!({}));
        
        // 1. Mandatory scrubbing
        if let Ok(sanitized) = serde_json::to_string(&ev).map(|s| SCRUBBER.scrub(&s)) {
            if let Ok(json) = serde_json::from_str(&sanitized) {
                ev = json;
            }
        }

        // 2. Reduce size for tokens
        if let Some(obj) = ev.as_object_mut() {
            Self::minify_evidence_object(obj, 300); // Reduced from 512 to 300
        }

        let verified = finding.evidence.primary.as_ref().map(|e| e.verified).unwrap_or(false);

        // Dense Encoding: Use single-letter keys and values where possible
        serde_json::json!({
            "id": finding.core.id,
            "s": finding.core.severity.as_char(),
            "cat": finding.core.category,
            "cvss": finding.enrichment.cvss_score,
            "cf": if verified { "V" } else { "P" }, // V=Verified, P=Potential
            "d": finding.core.description.chars().take(150).collect::<String>(), // Reduced from 200 to 150
            "ev": ev,
        })
    }

    /// Dense context compression for findings to achieve maximum token savings.
    pub fn compress_finding_dense(finding: &Finding) -> serde_json::Value {
        let mut ev = finding.evidence.primary.as_ref().map(|e| e.data.clone()).unwrap_or_else(|| serde_json::json!({}));
        
        if let Ok(sanitized) = serde_json::to_string(&ev).map(|s| SCRUBBER.scrub(&s)) {
            if let Ok(json) = serde_json::from_str(&sanitized) {
                ev = json;
            }
        }

        if let Some(obj) = ev.as_object_mut() {
            Self::minify_evidence_object(obj, 150); // Aggressive body limit (150 chars)
            obj.remove("raw_response"); // Remove raw_response completely to save tokens
        }

        let verified = finding.evidence.primary.as_ref().map(|e| e.verified).unwrap_or(false);

        serde_json::json!({
            "id": finding.core.id,
            "s": finding.core.severity.as_char(),
            "cat": finding.core.category,
            "cvss": finding.enrichment.cvss_score,
            "cf": if verified { "V" } else { "P" }, // V=Verified, P=Potential
            "d": finding.core.description.chars().take(100).collect::<String>(), // 100 char limit
            "ev": ev,
        })
    }


    pub fn compress_plugins(plugins: &[PluginMetadata]) -> Vec<serde_json::value::Value> {
        plugins.iter().map(|p| {
            serde_json::json!({
                "n": p.name,
                "caps": p.capabilities,
                "l": p.layer, // Shortened lyr to l
            })
        }).collect()
    }

    pub fn compress_target(target: &TargetHost) -> serde_json::value::Value {
        let tech_stack: Vec<String> = target.findings.iter()
            .filter(|f| f.core.category == Category::TechnologyStack)
            .filter_map(|f| f.evidence.primary.as_ref()?.data.get("plugins")?.as_object())
            .flat_map(|obj| obj.keys().cloned())
            .collect();

        serde_json::json!({
            "h": target.host,
            "ip": target.ip.as_deref().unwrap_or("?"),
            "t": format!("{:?}", target.target_type),
            "tech": tech_stack,
        })
    }

    /// Lean target compression for Tier 0 (skips O(n) tech stack search)
    pub fn compress_target_lean(target: &TargetHost) -> serde_json::value::Value {
        serde_json::json!({
            "h": target.host,
            "ip": target.ip.as_deref().unwrap_or("?"),
            "t": format!("{:?}", target.target_type),
        })
    }

    /// Ultra-aggressive compression for Swarm Planner
    pub fn compress_swarm_context(finding: &Finding, _target: &TargetHost) -> serde_json::Value {
        let mut base = Self::compress_finding(finding, RouteLevel::Local);
        
        if let Some(ev) = base.get_mut("ev").and_then(|e| e.as_object_mut()) {
            ev.remove("body");
            ev.remove("raw_response");
            Self::minify_headers(ev, &["server", "x-powered-by"]); // Keep server and x-powered-by in swarm context
        }
        base
    }

    /// Specialized compression for source code findings to save tokens.
    pub fn compress_source_aware_finding(finding: &Finding) -> serde_json::Value {
        let mut base = serde_json::json!({
            "id": finding.core.id,
            "cat": finding.core.category,
            "s": finding.core.severity.as_char(),
            "d": finding.core.description,
        });

        if let Some(ref evidence) = finding.evidence.primary {
            if let (Some(obj), Some(ev)) = (base.as_object_mut(), evidence.data.as_object()) {
                let mut compressed_ev = ev.clone();
                if let Some(val) = compressed_ev.get_mut("snippet") {
                    if let Some(s) = val.as_str() {
                        if s.len() > 200 { // Reduced from 300 to 200
                            *val = serde_json::json!(format!("{}...", &s[..200]));
                        }
                    }
                }
                obj.insert("ev".to_string(), serde_json::Value::Object(compressed_ev));
            }
        }
        base
    }

    // --- INTERNAL HELPERS TO PREVENT ARROW PATTERN ---

    fn minify_evidence_object(obj: &mut serde_json::Map<String, serde_json::Value>, body_limit: usize) {
        // Truncate bodies
        if let Some(val) = obj.get_mut("body") {
            if let Some(s) = val.as_str() {
                if s.len() > body_limit {
                    *val = serde_json::json!(format!("{}...", &s[..body_limit]));
                }
            }
        }

        // Hardening: Stripping noisy headers to save tokens
        // V15.1 Fix (AIP 2.1): Tactical headers MUST be preserved.
        let whitelist = vec![
            "location", "www-authenticate", "x-content-type-options", "server", "x-powered-by"
        ];

        Self::minify_headers(obj, &whitelist);
    }

    fn minify_headers(obj: &mut serde_json::Map<String, serde_json::Value>, whitelist: &[&str]) {
        if let Some(h_obj) = obj.get_mut("headers").and_then(|h| h.as_object_mut()) {
            h_obj.retain(|k, _| {
                let key = k.to_lowercase();
                
                // Strip session/auth noise
                if key.contains("cookie") || key.contains("auth") || key == "user-agent" {
                    return false;
                }

                whitelist.contains(&key.as_str())
            });
        }
    }

}
