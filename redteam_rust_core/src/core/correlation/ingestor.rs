use crate::models::{Finding, Category};
use crate::models::constants::*;
use super::CorrelationEngine;
use tracing::info;

pub struct Ingestor;

const MAX_NODES: usize = 10000;

impl Ingestor {
    pub fn ingest_finding(ce: &mut CorrelationEngine, finding: Finding) {
        let node_count = ce.get_graph().nodes.len();
        if node_count >= MAX_NODES && !ce.get_graph().nodes.contains_key(&finding.core.id) {
            tracing::warn!("🚨 V14.1 SOVEREIGN: CorrelationEngine node limit hit ({}). Skipping ingestion of {}.", MAX_NODES, finding.core.id);
            return;
        }

        let is_new = !ce.get_graph().nodes.contains_key(&finding.core.id);
        ce.get_graph_mut().add_node(finding.clone());
        
        if is_new {
            ce.mark_dirty();
            Self::correlate(ce, &finding);
        }
    }

    fn correlate(ce: &mut CorrelationEngine, new_finding: &Finding) {
        let existing_nodes: Vec<Finding> = ce.get_graph().nodes.values().cloned().collect();
        
        for existing in existing_nodes {
            if existing.core.id == new_finding.core.id { continue; }

            let evidence_new = new_finding.evidence.primary.as_ref();
            let evidence_existing = existing.evidence.primary.as_ref();

            // Rule 1: Category-based correlation
            match (&existing.core.category, &new_finding.core.category) {
                (Category::NetworkPort, Category::TechnologyStack) => {
                    ce.add_edge(&existing.core.id, &new_finding.core.id);
                },
                (Category::TechnologyStack, Category::Vulnerability) | (Category::Misconfiguration, Category::Vulnerability) => {
                    ce.add_edge(&existing.core.id, &new_finding.core.id);
                },
                (Category::Vulnerability, Category::CredentialLeak) | (Category::Vulnerability, Category::ExposedAsset) => {
                    ce.add_edge(&existing.core.id, &new_finding.core.id);
                },
                (Category::Windows, Category::Vulnerability) | (Category::Windows, Category::CredentialLeak) => {
                    ce.add_edge(&existing.core.id, &new_finding.core.id);
                },
                (Category::Windows, Category::Windows) => {
                    if let (Some(ev_ext), Some(ev_new)) = (evidence_existing, evidence_new) {
                        if let (Some(u_sid), Some(c_sid)) = (ev_ext.data.get("SID"), ev_new.data.get("SID")) {
                            if u_sid != c_sid {
                                info!("🔱 SOVEREIGN: Correlation AD relationship detected between {} and {}", existing.core.id, new_finding.core.id);
                                ce.add_edge(&existing.core.id, &new_finding.core.id);
                            }
                        }
                    }
                },
                (Category::CredentialLeak, Category::Vulnerability) => {
                    ce.add_edge(&existing.core.id, &new_finding.core.id);
                },
                _ => {
                    // API Attack Chain
                    if is_api_chain_finding(&existing) && is_api_chain_finding(new_finding) {
                        let url_a = existing.evidence.primary.as_ref().and_then(|e| e.data.get("url")).and_then(|v| v.as_str());
                        let url_b = new_finding.evidence.primary.as_ref().and_then(|e| e.data.get("url")).and_then(|v| v.as_str());
                        
                        if let (Some(ua), Some(ub)) = (url_a, url_b) {
                            let dom_a = extract_domain(ua);
                            let dom_b = extract_domain(ub);
                            if !dom_a.is_empty() && dom_a == dom_b {
                                ce.add_edge(&existing.core.id, &new_finding.core.id);
                                info!("🔱 SOVEREIGN: API Attack Chain link detected: {} <-> {}", existing.core.id, new_finding.core.id);
                            }
                        }
                    }
                }
            }

            // Source-Aware Endpoint correlation
            if let (Some(ev_ext), Some(ev_new)) = (evidence_existing, evidence_new) {
                if let (Some(a_type), Some(b_type)) = (ev_ext.data.get("type"), ev_new.data.get("type")) {
                    if a_type == "source_aware" || b_type == "source_aware" {
                        let a_end = ev_ext.data.get("endpoint").and_then(|v| v.as_str());
                        let b_end = ev_new.data.get("endpoint").and_then(|v| v.as_str());
                        
                        if let (Some(ae), Some(be)) = (a_end, b_end) {
                            if ae.to_lowercase().contains(&be.to_lowercase()) || be.to_lowercase().contains(&ae.to_lowercase()) {
                                ce.add_edge(&existing.core.id, &new_finding.core.id);
                            }
                        }
                    }
                }
            }

            // SSTI -> RCE Chain
            let is_ssti = existing.core.id == FINDING_SSTI;
            let is_rce = new_finding.core.id.starts_with("COMMIX-RCE");
            if is_ssti && is_rce {
                 if let (Some(ua), Some(ub)) = (get_url(&existing), get_url(new_finding)) {
                    let dom_a = extract_domain(ua);
                    let dom_b = extract_domain(ub);
                    if !dom_a.is_empty() && dom_a == dom_b {
                        ce.add_edge(&existing.core.id, &new_finding.core.id);
                    }
                }
            }
            
            // Reverse category rules
            match (&new_finding.core.category, &existing.core.category) {
                (Category::NetworkPort, Category::TechnologyStack) | (Category::TechnologyStack, Category::Vulnerability) | (Category::Misconfiguration, Category::Vulnerability) | (Category::Vulnerability, Category::CredentialLeak) | (Category::Vulnerability, Category::ExposedAsset) | (Category::Windows, Category::Vulnerability) | (Category::Windows, Category::CredentialLeak) | (Category::CredentialLeak, Category::Vulnerability) => {
                    ce.add_edge(&new_finding.core.id, &existing.core.id);
                },
                _ => {}
            }
        }
    }
}

fn extract_domain(url_str: &str) -> String {
    if let Ok(parsed) = url::Url::parse(url_str) {
        parsed.host_str().unwrap_or("").to_string()
    } else {
        String::new()
    }
}

fn get_url(f: &Finding) -> Option<&str> {
    f.evidence.primary.as_ref().and_then(|e| e.data.get("url")).and_then(|v| v.as_str())
}

fn is_api_chain_finding(f: &Finding) -> bool {
    matches!(
        f.core.id.as_str(),
        FINDING_GRAPHQL_INTROSPECTION
            | FINDING_PROTOTYPE_POLLUTION
            | FINDING_CORS_MISCONFIG
            | FINDING_WEB_CACHE_DECEPTION
            | FINDING_SSTI
            | FINDING_OPEN_REDIRECT
            | FINDING_WAYMORE_URL
    )
}
