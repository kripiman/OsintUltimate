use crate::plugins::{ScannerPlugin, Capability};
use crate::models::{TargetHost, Finding, Severity, Category};
use crate::utils::tool_detection::detect_tool;
use crate::models::constants::*;
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::{info, error};
use std::process::Stdio;
use tokio::process::Command;

pub struct GraphW00fScanner {
    binary_path: String,
}

impl Default for GraphW00fScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl GraphW00fScanner {
    pub fn new() -> Self {
        let path = detect_tool("graphw00f");
        Self {
            binary_path: path,
        }
    }
}

#[async_trait]
impl ScannerPlugin for GraphW00fScanner {
    fn name(&self) -> &'static str {
        PLUGIN_GRAPHW00F
    }

    fn metadata(&self) -> crate::plugins::PluginMetadata {
        crate::plugins::PluginMetadata {
            name: self.name().to_string(),
            description: "GraphQL fingerprinting tool to identify GraphQL engine and sensitive endpoints.".to_string(),
            target_type: crate::plugins::TargetType::Web,
            risk_level: crate::plugins::RiskLevel::Low,
            layer: crate::core::capability_layer::ScanLayer::Scanning,
            expected_duration: std::time::Duration::from_secs(120),
            capabilities: vec![Capability::GraphQL],
            cost: 3,
            category: "Enumeration".to_string(),
            mitre_attacks: vec!["T1595.002".to_string()],
            exploit_difficulty: crate::plugins::RiskLevel::Low,
            blackarch_category: None,
            is_destructive: false,
            poc_mode: false, ..Default::default() }
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::GraphQL]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability("graphw00f").await)
    }

    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        info!("GraphW00fScanner: fingerprinting GraphQL for {}", target.host);

        let mut findings = Vec::new();
        
        let target_url = target.extra_data.get("api_schema_url")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("https://{}", target.host)); // Default to https

        let child = Command::new(&self.binary_path)
            .arg("-t")
            .arg(&target_url)
            .arg("-f")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn();

        match child {
            Ok(c) => {
                let output = c.wait_with_output().await.context("Failed to wait for graphw00f")?;
                let content = String::from_utf8_lossy(&output.stdout);
                let content_lower = content.to_lowercase();
                
                if output.status.success() && (content_lower.contains("found") || content_lower.contains("engine") || content_lower.contains("technology")) {
                    findings.push(Finding::new(
                        FINDING_GRAPHQL_FINGERPRINT,
                        Category::TechnologyStack,
                        Severity::Info,
                        &format!("GraphQL engine fingerprinted at {}", target_url),
                        serde_json::json!({
                            "url": target_url,
                            "raw_output": content.trim(),
                            "tool": "graphw00f"
                        })
                    ));
                }
            }
            Err(e) => {
                error!("GraphW00fScanner failed to spawn: {}", e);
            }
        }

        Ok(findings)
    }
}
