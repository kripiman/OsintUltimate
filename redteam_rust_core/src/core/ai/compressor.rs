use crate::models::{Finding, Category, TargetHost};
use crate::plugins::PluginMetadata;
use super::types::RouteLevel;
use super::scrubber::SCRUBBER;

/// Helper to minify findings and plugins to save tokens.
pub struct ContextCompressor;

impl ContextCompressor {
    pub fn compress_finding(finding: &Finding, route_level: RouteLevel) -> serde_json::Value {
        let mut ev = finding.evidence.data.clone();
        
        // OPSEC 2026: Skip scrubbing for Local (Tier-0) to maximize context
        if route_level != RouteLevel::Local {
            let ev_str = serde_json::to_string(&ev).unwrap_or_default();
            let sanitized_str = SCRUBBER.scrub(&ev_str);
            if let Ok(sanitized_json) = serde_json::from_str(&sanitized_str) {
                ev = sanitized_json;
            }
        }

        // 2. Reduce size for tokens
        if let Some(obj) = ev.as_object_mut() {
            // Truncate large bodies
            if let Some(body) = obj.get_mut("body") {
                if let Some(s) = body.as_str() {
                    if s.len() > 512 {
                        *body = serde_json::json!(format!("{}... [TRUNCATED]", &s[..512]));
                    }
                }
            }
            // Strip noisy headers, keep security/tech ones
            if let Some(headers) = obj.get_mut("headers") {
                if let Some(h_obj) = headers.as_object_mut() {
                    let whitelist = [
                        "server", "x-powered-by", "content-security-policy", 
                        "x-frame-options", "strict-transport-security", "location",
                        "www-authenticate", "x-content-type-options"
                    ];
                    let keys: Vec<String> = h_obj.keys().cloned().collect();
                    for k in keys {
                        if !whitelist.contains(&k.to_lowercase().as_str()) {
                            h_obj.remove(&k);
                        }
                    }
                }
            }
        }

        serde_json::json!({
            "id": finding.id,
            "sev": finding.severity,
            "cat": finding.category,
            "cvss": finding.cvss_score,
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
        let mut tech_stack: Vec<String> = Vec::new();
        for finding in target.findings.iter() {
            if finding.category == Category::TechnologyStack {
                if let Some(plugins) = finding.evidence.data.get("plugins") {
                    if let Some(obj) = plugins.as_object() {
                        tech_stack.extend(obj.keys().cloned());
                    }
                }
            }
        }

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
        
        // Planner only needs high-level telemetry, not raw body samples
        if let Some(obj) = base.as_object_mut() {
            if let Some(ev) = obj.get_mut("ev").and_then(|e| e.as_object_mut()) {
                ev.remove("body");
                ev.remove("raw_response");
                if let Some(headers) = ev.get_mut("headers").and_then(|h| h.as_object_mut()) {
                    // Keep ONLY Server and Tech headers for planning
                    let critical = ["server", "x-powered-by"];
                    let keys: Vec<String> = headers.keys().cloned().collect();
                    for k in keys {
                        if !critical.contains(&k.to_lowercase().as_str()) {
                            headers.remove(&k);
                        }
                    }
                }
            }
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

        if let Some(obj) = base.as_object_mut() {
            if let Some(ev) = finding.evidence.data.as_object() {
                let mut compressed_ev = ev.clone();
                // Ultra-aggressive snippet truncation
                if let Some(snippet) = compressed_ev.get_mut("snippet") {
                    if let Some(s) = snippet.as_str() {
                        if s.len() > 300 {
                            *snippet = serde_json::json!(format!("{}... [TRUNCATED]", &s[..300]));
                        }
                    }
                }
                obj.insert("ev".to_string(), serde_json::Value::Object(compressed_ev));
            }
        }
        base
    }
}
