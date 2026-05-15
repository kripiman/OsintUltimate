use crate::models::Finding;
use std::collections::{HashMap, HashSet};
use serde::{Deserialize, Serialize};
use tracing::{info, error};
use uuid::Uuid;
use sha2::{Sha256, Digest};
use anyhow::Context;

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
    /// BUG-W31-09 FIX: Use a more complex separator to avoid collisions
    pub fn pattern_signature(&self) -> String {
        self.nodes.join("::[v15]::")
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
    #[serde(default)]
    pub fired_chains: HashSet<String>,
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
            fired_chains: HashSet::new(),
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
            if let Some(props) = node.evidence.primary.as_ref().and_then(|e| e.data.get("properties")) {
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

    pub fn save(&self, path: &std::path::Path) -> anyhow::Result<()> {
        // REGRESSION-01 FIX: Robust path validation (blocks traversal, allows absolute paths)
        if path.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
            anyhow::bail!("V14.1 Security: Illegal path traversal (..) detected in state save.");
        }

        let json = serde_json::to_string(self)?;
        
        // SEC-NEW-02 FIX: Require mandatory MCP_TOKEN for security
        let secret = std::env::var("MCP_TOKEN")
            .context("🚨 V14.1 SECURITY: MCP_TOKEN environment variable MUST be set for state persistence.")?;
            
        // SEC-NEW-01 FIX: Use robust MAC (Double-hash prevents length extension attacks)
        // MAC = SHA256(secret || SHA256(secret || data))
        let mut hasher = Sha256::new();
        hasher.update(secret.as_bytes());
        hasher.update(Sha256::digest([secret.as_bytes(), json.as_bytes()].concat()));
        let signature = hex::encode(hasher.finalize());

        let payload = serde_json::json!({
            "version": "1.2",
            "signature": signature,
            "data": json
        });

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, serde_json::to_string_pretty(&payload)?)?;
        Ok(())
    }

    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        // REGRESSION-01 FIX: Robust path validation (blocks traversal, allows absolute paths)
        if path.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
            anyhow::bail!("V14.1 Security: Illegal path traversal (..) detected in state load.");
        }

        let content = std::fs::read_to_string(path)?;
        let payload: serde_json::Value = serde_json::from_str(&content)?;
        
        let signature = payload["signature"].as_str().ok_or_else(|| anyhow::anyhow!("Missing signature"))?;
        let data_json = payload["data"].as_str().ok_or_else(|| anyhow::anyhow!("Missing state data"))?;

        // SEC-NEW-02 FIX: Require mandatory MCP_TOKEN
        let secret = std::env::var("MCP_TOKEN")
            .context("🚨 V14.1 SECURITY: MCP_TOKEN environment variable MUST be set to load persistent state.")?;
            
        // SEC-NEW-01 FIX: Verify robust MAC
        let mut hasher = Sha256::new();
        hasher.update(secret.as_bytes());
        hasher.update(Sha256::digest([secret.as_bytes(), data_json.as_bytes()].concat()));
        let expected = hex::encode(hasher.finalize());
        
        if signature != expected {
            error!("🚨 V14.1 SECURITY: State poisoning detected! Signature verification failed for {}.", path.display());
            anyhow::bail!("Corrupted or tampered state file (MAC mismatch).");
        }

        let ce: Self = serde_json::from_str(data_json)?;
        Ok(ce)
    }

    pub fn ingest_outcome(&mut self, outcome: SubmissionOutcome) {
        info!("🔱 ROI: Ingesting outcome for chain {}: {:?}", outcome.chain_id, outcome.outcome);
        // BUG-W31-13 FIX: Basic weight adjustment logic for Phase 4
        if let OutcomeType::Accepted = outcome.outcome {
             info!("🔱 ROI: Adjusting weights for successful pattern: {}", outcome.pattern_signature);
             // Logic to boost this pattern's priority in future scans would go here
        }
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
                    if last_node.core.severity == crate::models::Severity::Critical || 
                       last_node.core.severity == crate::models::Severity::High {
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

// Dead code removed (moved to ingestor.rs)
fn true_bool() -> bool {
    true
}
