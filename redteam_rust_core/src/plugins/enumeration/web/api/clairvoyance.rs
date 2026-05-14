use crate::plugins::{ScannerPlugin, Capability, PluginMetadata, RiskLevel, TargetType, GlobalConfig};
use crate::models::{TargetHost, Finding, Category, Severity, constants::*};
use crate::utils::tool_detection::detect_tool;
use crate::utils::executor::ExecutorMode;
use async_trait::async_trait;
use anyhow::Result;
use tracing::info;
use std::process::Stdio;

pub struct ClairvoyanceScanner {
    binary_path: String,
    wordlist_path: Option<String>,
}

impl ClairvoyanceScanner {
    pub fn new<M: ExecutorMode>(config: &GlobalConfig<M>) -> Self {
        let path = detect_tool("clairvoyance");
        Self {
            binary_path: path,
            wordlist_path: config.clairvoyance_wordlist_path.clone(),
        }
    }
}

#[async_trait]
impl ScannerPlugin for ClairvoyanceScanner {
    fn name(&self) -> &'static str {
        crate::models::PLUGIN_CLAIRVOYANCE
    }

    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: self.name().to_string(),
            description: "clairvoyance: GraphQL schema reconstruction via field suggestions (blind introspection).".to_string(),
            target_type: TargetType::Host,
            risk_level: RiskLevel::Safe,
            layer: crate::core::capability_layer::ScanLayer::Exploitation,
            expected_duration: std::time::Duration::from_secs(300),
            capabilities: vec![Capability::GraphQL],
            cost: 5,
            category: "Web".to_string(),
            ..Default::default()
        }
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::GraphQL]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability("clairvoyance").await)
    }

    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        let addr = target.ip.as_deref().unwrap_or(&target.host);
        // Usually clairvoyance needs a URL, let's assume http/https if not specified
        let url = if addr.starts_with("http") { addr.to_string() } else { format!("http://{}", addr) };

        info!("ClairvoyanceScanner: launching GraphQL reconstruction for {}", url);

        let mut cmd = tokio::process::Command::new(&self.binary_path);
        cmd.arg(&url)
           .stdout(Stdio::piped())
           .stderr(Stdio::null());
        
        if let Some(wp) = &self.wordlist_path {
            cmd.arg("-w").arg(wp);
        }

        let output = cmd.spawn()?.wait_with_output().await?;
        if !output.status.success() {
            return Ok(Vec::new());
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.contains("type Query") || stdout.contains("type Mutation") {
             return Ok(vec![
                Finding::builder(
                    FINDING_GRAPHQL_SUGGESTIONS,
                    Category::Vulnerability,
                    Severity::High,
                    &format!("GraphQL schema successfully reconstructed for {}", url)
                )
                .with_evidence(serde_json::json!({"schema": &stdout}))
                .build()
            ]);
        }

        Ok(Vec::new())
    }
}
