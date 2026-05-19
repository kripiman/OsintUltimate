use crate::models::Category;
use std::collections::HashSet;
use super::{AttackGraph, AttackPath};

/// Sovereign-grade Attack Path Analyzer.
/// Decoupled from CorrelationEngine to handle complex graph traversals.
pub struct GraphAnalyzer<'a> {
    graph: &'a AttackGraph,
}

const MAX_DEPTH: usize = 8;

impl<'a> GraphAnalyzer<'a> {
    pub fn new(graph: &'a AttackGraph) -> Self {
        Self { graph }
    }

    pub fn find_all_paths(&self) -> Vec<AttackPath> {
        let mut paths = Vec::new();
        let mut visited = HashSet::new();

        for source_id in self.graph.nodes.keys() {
            if self.is_root_node(source_id) {
                self.dfs_paths(source_id, &mut vec![], &mut paths, &mut visited, 0);
            }
        }

        paths.sort_by(|a, b| b.total_cvss.partial_cmp(&a.total_cvss).unwrap_or(std::cmp::Ordering::Equal));
        paths
    }

    pub fn find_paths_from_owned(&self, owned_nodes: &HashSet<String>) -> Vec<AttackPath> {
        let mut paths = Vec::new();
        let mut visited = HashSet::new();

        for source_sid in owned_nodes {
            let source_id = format!("AD-NODE-{}", source_sid);
            if self.graph.nodes.contains_key(&source_id) {
                self.dfs_paths(&source_id, &mut vec![], &mut paths, &mut visited, 0);
            }
        }
        paths
    }

    fn is_root_node(&self, node_id: &str) -> bool {
        if let Some(node) = self.graph.nodes.get(node_id) {
            matches!(node.core.category, Category::Recon | Category::NetworkPort | Category::TechnologyStack)
        } else {
            false
        }
    }

    fn dfs_paths(&self, current: &str, current_path: &mut Vec<String>, all_paths: &mut Vec<AttackPath>, visited: &mut HashSet<String>, depth: usize) {
        current_path.push(current.to_string());
        visited.insert(current.to_string());

        if depth >= MAX_DEPTH {
            self.record_path(current_path, all_paths);
        } else {
            let mut is_leaf = true;

            if let Some(neighbors) = self.graph.edges.get(current) {
                for neighbor in neighbors {
                    if !visited.contains(neighbor) {
                        is_leaf = false;
                        self.dfs_paths(neighbor, current_path, all_paths, visited, depth + 1);
                    }
                }
            }

            if is_leaf && current_path.len() > 1 {
                self.record_path(current_path, all_paths);
            }
        }

        visited.remove(current);
        current_path.pop();
    }

    fn record_path(&self, current_path: &Vec<String>, all_paths: &mut Vec<AttackPath>) {
        if current_path.is_empty() { return; }
        
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
            nodes: current_path.to_owned(),
            total_cvss,
            description: desc_parts.join(" -> "),
        });
    }
}
