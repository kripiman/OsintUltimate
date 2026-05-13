use crate::models::{Finding, Category};
use crate::models::constants::FINDING_ATTACK_PATH;
use std::collections::{HashMap, HashSet};
use serde::{Deserialize, Serialize};
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeType {
    Accepted,
    Rejected,
    Duplicate,
    Na,
    Informational,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmissionOutcome {
    pub chain_id: Uuid,
    pub pattern_signature: String,
    pub outcome: OutcomeType,
    pub payout_usd: Option<f64>,
}

pub mod ad_ingestor;
pub mod analyzer;
pub mod ingestor;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPath {
    pub nodes: Vec<String>, // Finding IDs
    pub total_cvss: f32,
    pub description: String,
}

impl AttackPath {
    /// Generates a stable signature for the attack chain pattern (Fase 4)
    pub fn pattern_signature(&self) -> String {
        self.nodes.join("->")
    }
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationEngine {
    graph: AttackGraph,
    owned_nodes: HashSet<String>, // SIDs of nodes we have credentials/sessions for
    #[serde(skip, default = "true_bool")]
    is_dirty: bool,
    #[serde(skip)]
    cached_paths: Vec<AttackPath>,
    #[serde(skip)]
    cached_critical_paths: Vec<AttackPath>,
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
            owned_nodes: HashSet::new(),
            is_dirty: true,
            cached_paths: Vec::new(),
            cached_critical_paths: Vec::new(),
        }
    }

    pub fn mark_node_as_owned(&mut self, sid: &str) {
        info!("🔱 SOVEREIGN: Node {} marked as OWNED.", sid);
        if self.owned_nodes.insert(sid.to_string()) {
            self.is_dirty = true;
        }
    }

    pub fn find_sid_by_username(&self, username: &str) -> Option<String> {
        let normalized_user = username.to_uppercase();
        for (id, node) in &self.graph.nodes {
            if let Some(props) = node.evidence.evidence.as_ref().and_then(|e| e.data.get("properties")) {
                if let Some(name) = props.get("name").and_then(|v| v.as_str()) {
                    let name_upper = name.to_uppercase();
                    let is_match = name_upper == normalized_user || 
                                   name_upper.starts_with(&format!("{}\\", normalized_user)) ||
                                   name_upper.starts_with(&format!("{}@", normalized_user)) ||
                                   name_upper.contains(&format!("\\{}", normalized_user));
                    
                    if is_match {
                        return Some(id.replace("AD-NODE-", ""));
                    }
                }
            }
        }
        None
    }

    pub fn get_graph_mut(&mut self) -> &mut AttackGraph {
        &mut self.graph
    }

    pub fn mark_dirty(&mut self) {
        self.is_dirty = true;
    }

    pub fn add_edge(&mut self, source_id: &str, target_id: &str) {
        info!("🔱 SOVEREIGN: Manually adding AttackGraph edge: {} -> {}", source_id, target_id);
        self.graph.add_edge(source_id, target_id);
        self.is_dirty = true;
    }

    pub fn get_graph(&self) -> &AttackGraph {
        &self.graph
    }

    pub fn save(&self, path: &str) -> anyhow::Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    pub fn load(path: &str) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let ce: Self = serde_json::from_str(&content)?;
        Ok(ce)
    }

    pub fn ingest_outcome(&mut self, outcome: SubmissionOutcome) {
        info!("🔱 ROI: Ingesting outcome for chain {}: {:?}", outcome.chain_id, outcome.outcome);
        // TODO: Implement weight adjustment logic in Fase 4
    }

    pub fn get_attack_paths(&mut self) -> Vec<AttackPath> {
        if !self.is_dirty && !self.cached_paths.is_empty() {
            return self.cached_paths.clone();
        }

        let analyzer = analyzer::GraphAnalyzer::new(&self.graph);
        let paths = analyzer.find_all_paths();

        self.cached_paths = paths.clone();
        // Do NOT reset is_dirty here because critical findings might still be stale
        paths
    }

    /// Phase 6: Returns critical attack paths from owned nodes.
    pub fn get_critical_paths(&mut self) -> Vec<AttackPath> {
        if !self.is_dirty && !self.cached_critical_paths.is_empty() {
            return self.cached_critical_paths.clone();
        }

        let analyzer = analyzer::GraphAnalyzer::new(&self.graph);
        let paths = analyzer.find_paths_from_owned(&self.owned_nodes);

        let mut critical_paths = Vec::new();
        for path in paths {
            if let Some(last_node_id) = path.nodes.last() {
                if let Some(last_node) = self.graph.nodes.get(last_node_id) {
                    if last_node.core.severity == crate::models::Severity::Critical {
                        critical_paths.push(path);
                    }
                }
            }
        }

        self.cached_critical_paths = critical_paths.clone();
        self.is_dirty = false;
        critical_paths
    }

    pub fn get_context_summary(&mut self, finding_id: &str) -> Option<String> {
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
}

fn extract_domain(url_str: &str) -> String {
    if let Ok(parsed) = url::Url::parse(url_str) {
        parsed.host_str().unwrap_or("").to_string()
    } else {
        url_str.to_string()
    }
}

fn true_bool() -> bool {
    true
}
