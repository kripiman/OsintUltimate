use crate::models::{Finding, Category, TargetHost};
use crate::plugins::PluginMetadata;
use super::types::RouteLevel;
use super::scrubber::SCRUBBER;

/// Helper to minify findings and plugins to save tokens.
pub struct ContextCompressor;

impl ContextCompressor {
    pub fn compress_finding(finding: &Finding, _route_level: RouteLevel) -> serde_json::Value {
        let mut ev = finding.evidence.data.clone();
        
        // 1. Mandatory scrubbing
        if let Ok(sanitized) = serde_json::to_string(&ev).map(|s| SCRUBBER.scrub(&s)) {
            if let Ok(json) = serde_json::from_str(&sanitized) {
                ev = json;
            }
        }

        // 2. Reduce size for tokens
        if let Some(obj) = ev.as_object_mut() {
            Self::minify_evidence_object(obj, 512, false);
        }

        serde_json::json!({
            "id": finding.id,
            "sev": finding.severity,
            "cat": finding.category,
            "cvss": finding.cvss_score,
            "conf": if finding.evidence.verified { "VERIFIED" } else { "POTENTIAL" },
            "desc": finding.description.chars().take(200).collect::<String>(),
            "ev": ev,
        })
    }

    pub fn compress_plugins(plugins: &[PluginMetadata]) -> Vec<serde_json::value::Value> {
        plugins.iter().map(|p| {
            serde_json::json!({
                "n": p.name,
                "caps": p.capabilities,
                "lyr": p.layer,
            })
        }).collect()
    }

    /// NEW V10: Compress target host info including tech stack for AI context.
    pub fn compress_target(target: &TargetHost) -> serde_json::value::Value {
        let tech_stack: Vec<String> = target.findings.iter()
            .filter(|f| f.category == Category::TechnologyStack)
            .filter_map(|f| f.evidence.data.get("plugins")?.as_object())
            .flat_map(|obj| obj.keys().cloned())
            .collect();

        serde_json::json!({
            "h": target.host,
            "ip": target.ip.as_deref().unwrap_or("unknown"),
            "type": format!("{:?}", target.target_type),
            "tech": tech_stack,
        })
    }

    /// NEW V4: Ultra-aggressive compression for Swarm Planner
    pub fn compress_swarm_context(finding: &Finding, _target: &TargetHost) -> serde_json::Value {
        let mut base = Self::compress_finding(finding, RouteLevel::Local);
        
        if let Some(ev) = base.get_mut("ev").and_then(|e| e.as_object_mut()) {
            ev.remove("body");
            ev.remove("raw_response");
            Self::minify_headers(ev, &["server", "x-powered-by"]);
        }
        base
    }

    /// NEW V11: Specialized compression for source code findings to save tokens.
    pub fn compress_source_aware_finding(finding: &Finding) -> serde_json::Value {
        let mut base = serde_json::json!({
            "id": finding.id,
            "cat": finding.category,
            "sev": finding.severity,
            "desc": finding.description,
        });

        if let (Some(obj), Some(ev)) = (base.as_object_mut(), finding.evidence.data.as_object()) {
            let mut compressed_ev = ev.clone();
            if let Some(val) = compressed_ev.get_mut("snippet") {
                if let Some(s) = val.as_str() {
                    if s.len() > 300 {
                        *val = serde_json::json!(format!("{}... [TRUNCATED]", &s[..300]));
                    }
                }
            }
            obj.insert("ev".to_string(), serde_json::Value::Object(compressed_ev));
        }
        base
    }

    // --- INTERNAL HELPERS TO PREVENT ARROW PATTERN ---

    fn minify_evidence_object(obj: &mut serde_json::Map<String, serde_json::Value>, body_limit: usize, planner_only: bool) {
        // Truncate bodies
        if let Some(val) = obj.get_mut("body") {
            if let Some(s) = val.as_str() {
                if s.len() > body_limit {
                    *val = serde_json::json!(format!("{}... [TRUNCATED]", &s[..body_limit]));
                }
            }
        }

        let whitelist = if planner_only {
            vec!["server", "x-powered-by"]
        } else {
            vec![
                "server", "x-powered-by", "content-security-policy", 
                "x-frame-options", "strict-transport-security", "location",
                "www-authenticate", "x-content-type-options"
            ]
        };

        Self::minify_headers(obj, &whitelist);
    }

    fn minify_headers(obj: &mut serde_json::Map<String, serde_json::Value>, whitelist: &[&str]) {
        if let Some(h_obj) = obj.get_mut("headers").and_then(|h| h.as_object_mut()) {
            h_obj.retain(|k, _| whitelist.contains(&k.to_lowercase().as_str()));
        }
    }

}
