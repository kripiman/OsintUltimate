// src/plugins/reconnaissance/osint/alterx.rs
// 🔧 AlterX: Subdomain permutation and generation
// ⚡ Async DiscoveryPlugin wrapper

use crate::plugins::{DiscoveryPlugin, Capability, DiscoveryResult};
use crate::models::{TargetHost, PLUGIN_ALTERX};
use crate::utils::tool_detection::detect_tool;
use async_trait::async_trait;
use anyhow::Result;
use tracing::{info, warn};
use std::process::Stdio;
use tokio::process::Command;

pub struct AlterXScanner {
    binary_path: String,
}

impl Default for AlterXScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl AlterXScanner {
    pub fn new() -> Self {
        let path = detect_tool("alterx");
        Self {
            binary_path: path,
        }
    }
}

#[async_trait]
impl DiscoveryPlugin for AlterXScanner {
    fn name(&self) -> &'static str {
        PLUGIN_ALTERX
    }

    fn metadata(&self) -> crate::plugins::PluginMetadata {
        crate::plugins::PluginMetadata {
            name: self.name().to_string(),
            description: "Fast subdomain permutation and generation using patterns and machine learning models.".to_string(),
            target_type: crate::plugins::TargetType::Host,
            risk_level: crate::plugins::RiskLevel::Safe,
            layer: crate::core::capability_layer::ScanLayer::Discovery,
            expected_duration: std::time::Duration::from_secs(60),
            capabilities: self.capabilities(),
            cost: 2,
            category: "Reconnaissance".to_string(),
            mitre_attacks: vec!["T1583.001".to_string()],
            exploit_difficulty: crate::plugins::RiskLevel::Low,
            blackarch_category: Some("recon".to_string()),
            is_destructive: false,
            poc_mode: true, ..Default::default() }
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::SubdomainEnumeration]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability("alterx").await)
    }

    async fn discover(&self, target: &TargetHost) -> Result<Vec<DiscoveryResult>> {
        info!("🧬 ALTERX: Generating subdomain permutations for {}", target.host);
        
        // alterx -i domain.com -silent
        let output = match tokio::time::timeout(
            std::time::Duration::from_secs(60),
            Command::new(&self.binary_path)
                .arg("-i")
                .arg(&target.host)
                .arg("-silent")
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .output()
        ).await {
            Ok(Ok(o)) => o,
            _ => {
                warn!("⚠️ ALTERX: Execution failed or timed out for {}", target.host);
                return Ok(Vec::new());
            }
        };

        let content = String::from_utf8_lossy(&output.stdout);
        let permutations: Vec<String> = content.lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();

        info!("✨ ALTERX: Generated {} permutations for {}", permutations.len(), target.host);
        Ok(permutations.into_iter().map(|s| DiscoveryResult { host: s, metadata: serde_json::json!({}) }).collect())
    }
}
