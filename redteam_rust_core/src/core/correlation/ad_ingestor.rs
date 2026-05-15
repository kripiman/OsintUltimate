use anyhow::Result;
use crate::models::{Finding, Category, Severity};
use crate::core::correlation::CorrelationEngine;
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::Mutex;
use std::fs::File;
use std::io::BufReader;
use tracing::info;

/// V14.1 AD Ingestor: Professional BloodHound JSON parser.
/// Maps AD relationships to AttackGraph edges.
pub struct AdIngestor {
    engine: Arc<Mutex<CorrelationEngine>>,
}

#[derive(Deserialize)]
struct BloodHoundNode {
    #[serde(rename = "ObjectIdentifier")]
    id: String,
    #[serde(rename = "Properties")]
    properties: serde_json::Value,
}

#[derive(Deserialize)]
struct BloodHoundEdge {
    #[serde(rename = "StartNode")]
    start: String,
    #[serde(rename = "EndNode")]
    end: String,
    #[serde(rename = "SelectedEdgeType")]
    edge_type: String,
}

#[derive(Deserialize)]
struct BloodHoundData {
    pub data: Vec<BloodHoundNode>,
}

#[derive(Deserialize)]
struct BloodHoundEdges {
    pub data: Vec<BloodHoundEdge>,
}

impl AdIngestor {
    pub fn new(engine: Arc<Mutex<CorrelationEngine>>) -> Self {
        Self { engine }
    }

    /// Ingests a BloodHound JSON file (e.g. users.json, computers.json).
    pub async fn ingest_nodes(&self, path: &str, category_str: &str) -> Result<()> {
        info!("🔱 V14.1 SOVEREIGN: Ingesting AD nodes from {}...", path);
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        
        let bh_data: BloodHoundData = serde_json::from_reader(reader)?;
        
        let mut engine = self.engine.lock().await;
        for node in bh_data.data {
            let title = node.properties.get("name").and_then(|v| v.as_str()).unwrap_or(&node.id).to_string();
            
            // Phase 6.1 / BUG-1: BloodHound CE emits admincount as integer (0/1), not bool.
            // SharpHound 2.0 / CE: Properties may be nested or flat.
            let _props = node.properties.as_object();
            
            let is_high_value = node.properties.get("highvalue")
                .or_else(|| node.properties.get("HighValue"))
                .and_then(|v| v.as_bool().or_else(|| v.as_i64().map(|n| n > 0)))
                .unwrap_or(false);
            
            let is_admin = node.properties.get("admincount")
                .or_else(|| node.properties.get("AdminCount"))
                .and_then(|v| v.as_bool().or_else(|| v.as_i64().map(|n| n > 0)))
                .unwrap_or(false);
            
            let severity = if is_high_value || is_admin {
                Severity::Critical
            } else {
                Severity::Info
            };

            let finding = Finding::new(
                &format!("AD-NODE-{}", node.id),
                Category::Windows,
                severity,
                &format!("AD Object discovered: {}", title),
                serde_json::json!({
                    "SID": node.id,
                    "type": category_str,
                    "properties": node.properties,
                    "is_high_value": is_high_value,
                    "is_admin": is_admin
                })
            );
            crate::core::correlation::ingestor::Ingestor::ingest_finding(&mut engine, finding);
        }
        
        Ok(())
    }

    /// Ingests BloodHound relationship data.
    pub async fn ingest_edges(&self, path: &str) -> Result<()> {
        info!("🔱 V14.1 SOVEREIGN: Ingesting AD relationships from {}...", path);
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        
        // Note: For multi-GB files, we should use a stream deserializer.
        let bh_edges: BloodHoundEdges = serde_json::from_reader(reader)?;
        
        let mut engine = self.engine.lock().await;
        for edge in bh_edges.data {
            let source = format!("AD-NODE-{}", edge.start);
            let target = format!("AD-NODE-{}", edge.end);
            
            info!("🔱 V14.1 AD-LINK: {} --[{}]--> {}", edge.start, edge.edge_type, edge.end);
            engine.add_edge(&source, &target);
        }
        
        Ok(())
    }
}
