use crate::plugins::{ScannerPlugin, Capability};
use crate::models::{TargetHost, Finding, Severity, Category};
use crate::utils::tool_detection::detect_tool;
use async_trait::async_trait;
use anyhow::Result;
use tracing::{info, warn};
use std::sync::Arc;
pub struct BloodHoundScanner {
    binary_path: String,
    executor: Arc<crate::utils::executor::StealthExecutor>,
    correlation_engine: Arc<tokio::sync::Mutex<crate::core::correlation::CorrelationEngine>>,
}
impl BloodHoundScanner {
    pub fn new(executor: Arc<crate::utils::executor::StealthExecutor>, ce: Arc<tokio::sync::Mutex<crate::core::correlation::CorrelationEngine>>) -> Self {
        let path = detect_tool("bloodhound-python");
        Self {
            binary_path: path,
            executor,
            correlation_engine: ce,
        }
    }

    async fn ingest_results(&self) -> Result<()> {
        info!("🔱 V14.1 SOVEREIGN: Commencing BloodHound result ingestion into CorrelationEngine...");
        
        let ingestor = crate::core::correlation::ad_ingestor::AdIngestor::new(self.correlation_engine.clone());
        
        // Find generated JSON files in the current directory (default for bloodhound-python)
        let entries = std::fs::read_dir(".")?;
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            if let Some(ext) = path.extension() {
                if ext == "json" {
                    let path_str = path.to_string_lossy();
                    if path_str.contains("users.json") {
                        ingestor.ingest_nodes(&path_str, "User").await?;
                    } else if path_str.contains("computers.json") {
                        ingestor.ingest_nodes(&path_str, "Computer").await?;
                    } else if path_str.contains("groups.json") {
                        ingestor.ingest_nodes(&path_str, "Group").await?;
                    } else if path_str.contains("containers.json") {
                        ingestor.ingest_nodes(&path_str, "Container").await?;
                    } else if path_str.contains("ous.json") {
                        ingestor.ingest_nodes(&path_str, "OU").await?;
                    } else if path_str.contains("domains.json") {
                        ingestor.ingest_nodes(&path_str, "Domain").await?;
                    } else if path_str.contains("edges.json") || path_str.contains("relationships.json") {
                        ingestor.ingest_edges(&path_str).await?;
                    }
                }
            }
        }
        
        Ok(())
    }
}
#[async_trait]
impl ScannerPlugin for BloodHoundScanner {
    fn name(&self) -> &'static str {
        crate::models::PLUGIN_BLOODHOUND
    }
        fn metadata(&self) -> crate::plugins::PluginMetadata {
        crate::plugins::PluginMetadata {
            name: self.name().to_string(),
            description: "Automated security analysis using this plugin.".to_string(),
            target_type: crate::plugins::TargetType::Host,
            risk_level: crate::plugins::RiskLevel::Medium,
            layer: crate::core::capability_layer::ScanLayer::PostExploitation,
            expected_duration: std::time::Duration::from_secs(300),
            capabilities: self.capabilities(),
            cost: 5,
            category: "Lateral Movement".to_string(),
            mitre_attacks: vec![],
            remediation_difficulty: crate::plugins::RiskLevel::Medium,
            blackarch_category: None,
            is_destructive: false,
            poc_mode: false,
        }
    }
    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::ActiveDirectory]
    }
    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability("bloodhound").await)
    }
    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        info!("🔱 V14.1 SOVEREIGN: Collecting AD data from {} via StealthExecutor...", target.host);
        
        let args = vec![
            "-d".to_string(), target.host.clone(),
            "-c".to_string(), "All".to_string(),
            "--zip".to_string(),
        ];

        info!("🛡️ V14.1 SOVEREIGN: Dispatching proxied BloodHound collection via StealthExecutor.");
        let output = self.executor.execute_and_wait(&self.binary_path, args).await?;
        
        let mut findings = Vec::new();
        let content = String::from_utf8_lossy(&output.stdout);
        
        if output.status.success() {
            findings.push(Finding::new(
                "AD-DATA-COLLECTED",
                Category::Windows,
                Severity::Info,
                &format!("Active Directory data successfully collected from {}.", target.host),
                serde_json::json!({ "stdout": content.trim() })
            ));

            // V14.1 Ingestion Pipeline
            self.ingest_results().await?;
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!("⚠️ BloodHound collection failed: {}", stderr);
        }

        Ok(findings)
    }
}
