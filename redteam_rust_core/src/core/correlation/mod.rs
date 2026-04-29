use crate::models::{Finding, Category};
use crate::models::constants::{FINDING_GRAPHQL_INTROSPECTION, FINDING_PROTOTYPE_POLLUTION, FINDING_CORS_MISCONFIG, FINDING_WEB_CACHE_DECEPTION, FINDING_SSTI};
use std::collections::{HashMap, HashSet};
use serde::{Deserialize, Serialize};
use tracing::info;

pub mod ad_ingestor;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPath {
    pub nodes: Vec<String>, // Finding IDs
    pub total_cvss: f32,
    pub description: String,
}

#[derive(Default, Debug, Clone)]
pub struct AttackGraph {
    pub nodes: HashMap<String, Finding>,
    pub edges: HashMap<String, Vec<String>>, // Source ID -> Target IDs
}

impl AttackGraph {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_node(&mut self, finding: Finding) {
        self.nodes.insert(finding.core.id.clone(), finding);
    }

    pub fn add_edge(&mut self, source_id: &str, target_id: &str) {
        self.edges.entry(source_id.to_string()).or_default().push(target_id.to_string());
    }
}

pub struct CorrelationEngine {
    graph: AttackGraph,
}

impl Default for CorrelationEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl CorrelationEngine {
    pub fn new() -> Self {
        Self {
            graph: AttackGraph::new(),
        }
    }

    pub fn add_finding(&mut self, finding: Finding) {
        let is_new = !self.graph.nodes.contains_key(&finding.core.id);
        self.graph.add_node(finding.clone());
        
        if is_new {
            self.correlate_new_finding(&finding);
        }
    }

    pub fn add_edge(&mut self, source_id: &str, target_id: &str) {
        info!("🔱 V14.1 SOVEREIGN: Manually adding AttackGraph edge: {} -> {}", source_id, target_id);
        self.graph.add_edge(source_id, target_id);
    }

    fn correlate_new_finding(&mut self, new_finding: &Finding) {
        let existing_nodes: Vec<Finding> = self.graph.nodes.values().cloned().collect();
        
        for existing in existing_nodes {
            if existing.core.id == new_finding.core.id { continue; }

            let evidence_new = new_finding.evidence.evidence.as_ref();
            let evidence_existing = existing.evidence.evidence.as_ref();

            // Rule 1: Port -> Service/Tech -> Vulnerability -> Exploit
            match (&existing.core.category, &new_finding.core.category) {
                (Category::NetworkPort, Category::TechnologyStack) => {
                    self.graph.add_edge(&existing.core.id, &new_finding.core.id);
                },
                (Category::TechnologyStack, Category::Vulnerability) | (Category::Misconfiguration, Category::Vulnerability) => {
                    self.graph.add_edge(&existing.core.id, &new_finding.core.id);
                },
                (Category::Vulnerability, Category::CredentialLeak) | (Category::Vulnerability, Category::ExposedAsset) => {
                    self.graph.add_edge(&existing.core.id, &new_finding.core.id);
                },
                (Category::Windows, Category::Vulnerability) | (Category::Windows, Category::CredentialLeak) => {
                    self.graph.add_edge(&existing.core.id, &new_finding.core.id);
                },
                (Category::Windows, Category::Windows) => {
                    if let (Some(ev_ext), Some(ev_new)) = (evidence_existing, evidence_new) {
                        if let (Some(u_sid), Some(c_sid)) = (ev_ext.data.get("SID"), ev_new.data.get("SID")) {
                            if u_sid != c_sid {
                                info!("🔱 V14.1 SOVEREIGN: Correlation AD relationship detected between {} and {}", existing.core.id, new_finding.core.id);
                                self.graph.add_edge(&existing.core.id, &new_finding.core.id);
                            }
                        }
                    }
                },
                (Category::CredentialLeak, Category::Vulnerability) => {
                    self.graph.add_edge(&existing.core.id, &new_finding.core.id);
                },
                _ => {
                    // Rule 5: API Attack Chain (InQL -> Ppmap -> Corsy -> WCD)
                    let is_api_vuln_a = is_api_chain_finding(&existing);
                    let is_api_vuln_b = is_api_chain_finding(new_finding);

                    if is_api_vuln_a && is_api_vuln_b {
                        let url_a = existing.evidence.evidence.as_ref().and_then(|e| e.data.get("url")).and_then(|v| v.as_str());
                        let url_b = new_finding.evidence.evidence.as_ref().and_then(|e| e.data.get("url")).and_then(|v| v.as_str());
                        
                        if let (Some(ua), Some(ub)) = (url_a, url_b) {
                            if extract_domain(ua) == extract_domain(ub) {
                                self.graph.add_edge(&existing.core.id, &new_finding.core.id);
                                info!("🔱 V14.1 SOVEREIGN: API Attack Chain link detected: {} <-> {}", existing.core.id, new_finding.core.id);
                            }
                        }
                    }
                }
            }

            // Rule 4: SAST Endpoint -> DAST Finding (Source-Aware Correlation)
            if let (Some(ev_ext), Some(ev_new)) = (evidence_existing, evidence_new) {
                if let (Some(a_type), Some(b_type)) = (ev_ext.data.get("type"), ev_new.data.get("type")) {
                    if a_type == "source_aware" || b_type == "source_aware" {
                        let a_end = ev_ext.data.get("endpoint").and_then(|v| v.as_str());
                        let b_end = ev_new.data.get("endpoint").and_then(|v| v.as_str());
                        
                        if let (Some(ae), Some(be)) = (a_end, b_end) {
                            if ae.to_lowercase().contains(&be.to_lowercase()) || be.to_lowercase().contains(&ae.to_lowercase()) {
                                self.graph.add_edge(&existing.core.id, &new_finding.core.id);
                            }
                        }
                    }
                }
            }
            
            // Rule 6: SSTI -> RCE Chain (Tplmap -> Commix)
            let is_ssti = existing.core.id == FINDING_SSTI;
            let is_rce = new_finding.core.id.starts_with("COMMIX-RCE");
            if is_ssti && is_rce {
                let url_a = existing.evidence.evidence.as_ref().and_then(|e| e.data.get("url")).and_then(|v| v.as_str());
                let url_b = new_finding.evidence.evidence.as_ref().and_then(|e| e.data.get("url")).and_then(|v| v.as_str());
                
                if let (Some(ua), Some(ub)) = (url_a, url_b) {
                    if extract_domain(ua) == extract_domain(ub) {
                        self.graph.add_edge(&existing.core.id, &new_finding.core.id);
                        info!("🔱 V14.3 SOVEREIGN: SSTI -> RCE chain link detected: {} -> {}", existing.core.id, new_finding.core.id);
                    }
                }
            }
            
            // Reverse Rule 6
            let is_ssti_new = new_finding.core.id == FINDING_SSTI;
            let is_rce_old = existing.core.id.starts_with("COMMIX-RCE");
            if is_ssti_new && is_rce_old {
                let url_a = existing.evidence.evidence.as_ref().and_then(|e| e.data.get("url")).and_then(|v| v.as_str());
                let url_b = new_finding.evidence.evidence.as_ref().and_then(|e| e.data.get("url")).and_then(|v| v.as_str());
                
                if let (Some(ua), Some(ub)) = (url_a, url_b) {
                    if extract_domain(ua) == extract_domain(ub) {
                        self.graph.add_edge(&new_finding.core.id, &existing.core.id);
                        info!("🔱 V14.3 SOVEREIGN: SSTI -> RCE chain link detected: {} -> {}", new_finding.core.id, existing.core.id);
                    }
                }
            }
            
            // Reverse rules
            match (&new_finding.core.category, &existing.core.category) {
                (Category::NetworkPort, Category::TechnologyStack) => {
                    self.graph.add_edge(&new_finding.core.id, &existing.core.id);
                },
                (Category::TechnologyStack, Category::Vulnerability) | (Category::Misconfiguration, Category::Vulnerability) => {
                    self.graph.add_edge(&new_finding.core.id, &existing.core.id);
                },
                (Category::Vulnerability, Category::CredentialLeak) | (Category::Vulnerability, Category::ExposedAsset) => {
                    self.graph.add_edge(&new_finding.core.id, &existing.core.id);
                },
                (Category::Windows, Category::Vulnerability) | (Category::Windows, Category::CredentialLeak) => {
                    self.graph.add_edge(&new_finding.core.id, &existing.core.id);
                },
                (Category::CredentialLeak, Category::Vulnerability) => {
                    self.graph.add_edge(&new_finding.core.id, &existing.core.id);
                },
                _ => {}
            }
        }
    }

    pub fn get_attack_paths(&self) -> Vec<AttackPath> {
        let mut paths = Vec::new();
        let mut visited = HashSet::new();

        for source_id in self.graph.nodes.keys() {
            if self.is_root_node(source_id) {
                self.dfs_paths(source_id, &mut vec![], &mut paths, &mut visited);
            }
        }

        paths.sort_by(|a, b| b.total_cvss.partial_cmp(&a.total_cvss).unwrap_or(std::cmp::Ordering::Equal));
        paths
    }

    fn is_root_node(&self, node_id: &str) -> bool {
        if let Some(node) = self.graph.nodes.get(node_id) {
            matches!(node.core.category, Category::Recon | Category::NetworkPort | Category::TechnologyStack)
        } else {
            false
        }
    }

    pub fn get_context_summary(&self, finding_id: &str) -> Option<String> {
        let paths = self.get_attack_paths();
        let relevant_path = paths.iter().find(|p| p.nodes.contains(&finding_id.to_string()))?;

        let mut context_nodes = Vec::new();
        for node_id in &relevant_path.nodes {
            if let Some(node) = self.graph.nodes.get(node_id) {
                context_nodes.push(format!("{:?}", node.core.category));
            }
            if node_id == finding_id { break; }
        }

        Some(context_nodes.join(" -> "))
    }

    fn dfs_paths(&self, current: &str, current_path: &mut Vec<String>, all_paths: &mut Vec<AttackPath>, visited: &mut HashSet<String>) {
        current_path.push(current.to_string());
        visited.insert(current.to_string());

        let mut is_leaf = true;

        if let Some(neighbors) = self.graph.edges.get(current) {
            for neighbor in neighbors {
                if !visited.contains(neighbor) {
                    is_leaf = false;
                    self.dfs_paths(neighbor, current_path, all_paths, visited);
                }
            }
        }

        if is_leaf && current_path.len() > 1 {
            let mut total_cvss = 0.0;
            let mut desc_parts = Vec::new();

            for id in current_path.iter() {
                if let Some(node) = self.graph.nodes.get(id) {
                    total_cvss += node.enrichment.cvss_score.unwrap_or(0.0);
                    desc_parts.push(format!("{:?}", node.core.category));
                }
            }
            
            if !current_path.is_empty() {
                 total_cvss /= current_path.len() as f32;
            }

            all_paths.push(AttackPath {
                nodes: current_path.clone(),
                total_cvss,
                description: desc_parts.join(" -> "),
            });
        }

        visited.remove(current);
        current_path.pop();
    }
}

fn extract_domain(url_str: &str) -> String {
    if let Ok(parsed) = url::Url::parse(url_str) {
        parsed.host_str().unwrap_or("").to_string()
    } else {
        url_str.to_string()
    }
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
    )
}
