use crate::models::{Finding, Category};
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
        self.nodes.insert(finding.id.clone(), finding);
    }

    pub fn add_edge(&mut self, source_id: &str, target_id: &str) {
        self.edges.entry(source_id.to_string()).or_default().push(target_id.to_string());
    }
}

pub struct CorrelationEngine {
    graph: AttackGraph,
}

impl CorrelationEngine {
    pub fn new() -> Self {
        Self {
            graph: AttackGraph::new(),
        }
    }

    pub fn add_finding(&mut self, finding: Finding) {
        let is_new = !self.graph.nodes.contains_key(&finding.id);
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
        // Basic heuristic correlation rules
        let existing_nodes: Vec<Finding> = self.graph.nodes.values().cloned().collect();
        
        for existing in existing_nodes {
            if existing.id == new_finding.id { continue; }

            // Rule 1: Port -> Service/Tech -> Vulnerability -> Exploit
            match (&existing.category, &new_finding.category) {
                (Category::NetworkPort, Category::TechnologyStack) => {
                    self.graph.add_edge(&existing.id, &new_finding.id);
                },
                (Category::TechnologyStack, Category::Vulnerability) | (Category::Misconfiguration, Category::Vulnerability) => {
                    self.graph.add_edge(&existing.id, &new_finding.id);
                },
                (Category::Vulnerability, Category::CredentialLeak) | (Category::Vulnerability, Category::ExposedAsset) => {
                    self.graph.add_edge(&existing.id, &new_finding.id);
                },
                (Category::Windows, Category::Vulnerability) | (Category::Windows, Category::CredentialLeak) => {
                    // AD Sovereignty: Link discovered AD objects to potential strike vectors
                    self.graph.add_edge(&existing.id, &new_finding.id);
                },
                (Category::Windows, Category::Windows) => {
                    // V14.1 AD Path Ingestion: Link related AD objects (e.g. User belongs to Group, Group has admin on Computer)
                    if let (Some(u_sid), Some(c_sid)) = (existing.evidence.data.get("SID"), new_finding.evidence.data.get("SID")) {
                         if u_sid != c_sid {
                             info!("🔱 V14.1 SOVEREIGN: Correlation AD relationship detected between {} and {}", existing.id, new_finding.id);
                             self.graph.add_edge(&existing.id, &new_finding.id);
                         }
                    }
                },
                _ => {}
            }


            // Rule 4: SAST Endpoint -> DAST Finding (Source-Aware Correlation)
            if let (Some(a_type), Some(b_type)) = (existing.evidence.data.get("type"), new_finding.evidence.data.get("type")) {
                if a_type == "source_aware" || b_type == "source_aware" {
                    let a_end = existing.evidence.data.get("endpoint").and_then(|v| v.as_str());
                    let b_end = new_finding.evidence.data.get("endpoint").and_then(|v| v.as_str());
                    
                    if let (Some(ae), Some(be)) = (a_end, b_end) {
                        if ae.to_lowercase().contains(&be.to_lowercase()) || be.to_lowercase().contains(&ae.to_lowercase()) {
                            self.graph.add_edge(&existing.id, &new_finding.id);
                        }
                    }
                }
            }
            
            // Reverse rules
            match (&new_finding.category, &existing.category) {
                (Category::NetworkPort, Category::TechnologyStack) => {
                    self.graph.add_edge(&new_finding.id, &existing.id);
                },
                (Category::TechnologyStack, Category::Vulnerability) | (Category::Misconfiguration, Category::Vulnerability) => {
                    self.graph.add_edge(&new_finding.id, &existing.id);
                },
                (Category::Vulnerability, Category::CredentialLeak) | (Category::Vulnerability, Category::ExposedAsset) => {
                    self.graph.add_edge(&new_finding.id, &existing.id);
                },
                (Category::Windows, Category::Vulnerability) | (Category::Windows, Category::CredentialLeak) => {
                    self.graph.add_edge(&new_finding.id, &existing.id);
                },
                _ => {}
            }
        }
    }

    pub fn get_attack_paths(&self) -> Vec<AttackPath> {
        let mut paths = Vec::new();
        let mut visited = HashSet::new();

        for (source_id, _) in &self.graph.nodes {
            // Find root nodes (e.g., Recon, NetworkPort)
            if self.is_root_node(source_id) {
                self.dfs_paths(source_id, &mut vec![], &mut paths, &mut visited);
            }
        }

        // Sort paths by total CVSS descending
        paths.sort_by(|a, b| b.total_cvss.partial_cmp(&a.total_cvss).unwrap_or(std::cmp::Ordering::Equal));
        paths
    }

    fn is_root_node(&self, node_id: &str) -> bool {
        if let Some(node) = self.graph.nodes.get(node_id) {
            matches!(node.category, Category::Recon | Category::NetworkPort | Category::TechnologyStack)
        } else {
            false
        }
    }

    pub fn get_context_summary(&self, finding_id: &str) -> Option<String> {
        let paths = self.get_attack_paths();
        // Buscar la ruta más relevante (mayor CVSS o más larga) que contenga este hallazgo
        let relevant_path = paths.iter()
            .filter(|p| p.nodes.contains(&finding_id.to_string()))
            .next()?;

        // Truncar la ruta hasta el hallazgo actual para dar contexto de "cómo llegamos aquí"
        let mut context_nodes = Vec::new();
        for node_id in &relevant_path.nodes {
            if let Some(node) = self.graph.nodes.get(node_id) {
                context_nodes.push(format!("{:?}", node.category));
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
            // Calculate total CVSS and build description
            let mut total_cvss = 0.0;
            let mut desc_parts = Vec::new();

            for id in current_path.iter() {
                if let Some(node) = self.graph.nodes.get(id) {
                    total_cvss += node.cvss_score.unwrap_or(0.0);
                    desc_parts.push(format!("{:?}", node.category));
                }
            }
            
            // simple normalization
            if current_path.len() > 0 {
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
