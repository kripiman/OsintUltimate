use crate::core::correlation::CorrelationEngine;
use crate::models::Finding;
use std::path::PathBuf;

/// Returns the absolute path for CE state persistence.
pub fn ce_state_path() -> PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join("osint-ultimate")
        .join("swarm_ce_state.json")
}

pub fn process_correlation(
    ce: &mut CorrelationEngine,
    finding: &Finding,
    scope_id: &str,
    seen_ids: &std::collections::HashSet<String>,
) -> Vec<Finding> {
    crate::core::correlation::ingestor::Ingestor::ingest_finding(ce, finding.clone());
    
    // Phase 6: Mark owned nodes based on credentials
    if finding.core.id == crate::models::constants::FINDING_NTLM_HASH_CAPTURED || 
       finding.core.id == crate::models::constants::FINDING_CREDENTIALS_FOUND {
        let sid = finding.evidence.primary.as_ref()
            .and_then(|e| e.data.get("SID"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        
        let resolved_sid = if sid.is_none() {
            finding.evidence.primary.as_ref()
                .and_then(|e| e.data.get("username").or_else(|| e.data.get("user")))
                .and_then(|v| v.as_str())
                .and_then(|u| ce.find_sid_by_username(u))
        } else {
            sid
        };

        if let Some(s) = resolved_sid {
            ce.mark_node_as_owned(&s);
        }
    }
    
    let paths = ce.get_critical_paths();
    let graph = ce.get_graph();

    paths.into_iter()
        .filter(|path| !seen_ids.contains(&format!("{}-{}", crate::models::constants::FINDING_ATTACK_PATH, path.pattern_signature())))
        .map(|path| {
            let signature = path.pattern_signature();
            let next_hop_host = path.nodes.iter().skip(1)
                .find_map(|node_id| {
                    let node = graph.nodes.get(node_id)?;
                    let props = node.evidence.primary.as_ref()?.data.get("properties")?;
                    let is_computer = node.evidence.primary.as_ref()?.data.get("type").and_then(|v| v.as_str()) == Some("Computer");
                    if is_computer {
                        props.get("dNSHostName").or_else(|| props.get("name")).and_then(|v| v.as_str()).map(|s| s.to_string())
                    } else { None }
                });

            let mut f = Finding::new(
                &format!("{}-{}", crate::models::constants::FINDING_ATTACK_PATH, signature),
                crate::models::Category::Windows,
                crate::models::Severity::High,
                &format!("Critical Attack Path detected: {}", path.description),
                serde_json::json!({
                    "nodes": path.nodes,
                    "description": path.description,
                    "total_cvss": path.total_cvss,
                    "signature": signature,
                    "host": next_hop_host
                })
            );
            f.core.scope_id = scope_id.to_string();
            f
        })
        .collect()
}
