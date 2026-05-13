use crate::plugins::{ScannerPlugin, Capability, TargetType, RiskLevel};
use crate::models::{TargetHost, Finding, Severity, Category};
use crate::utils::{detect_tool, check_tool_availability};
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::{info, warn, error};
use std::process::Stdio;
use tokio::process::Command;
use crate::models::constants::*;

pub struct X8Scanner {
    binary_path: String,
}

impl Default for X8Scanner {
    fn default() -> Self {
        Self::new()
    }
}

impl X8Scanner {
    pub fn new() -> Self {
        let path = detect_tool("x8");
        Self {
            binary_path: path,
        }
    }
}

#[async_trait]
impl ScannerPlugin for X8Scanner {
    fn name(&self) -> &'static str {
        PLUGIN_X8
    }

    fn metadata(&self) -> crate::plugins::PluginMetadata {
        crate::plugins::PluginMetadata {
            name: self.name().to_string(),
            description: "High-performance parameter discovery (Rust-native). Discover hidden query parameters and headers.".to_string(),
            target_type: TargetType::Web,
            risk_level: RiskLevel::Medium,
            layer: crate::core::capability_layer::ScanLayer::Scanning,
            expected_duration: std::time::Duration::from_secs(180),
            capabilities: vec![Capability::VulnerabilityScanning],
            cost: 4,
            category: "Enumeration".to_string(),
            mitre_attacks: vec!["T1595.002".to_string()],
            exploit_difficulty: RiskLevel::Low,
            blackarch_category: Some("webapp".to_string()),
            is_destructive: false,
            poc_mode: true, ..Default::default() }
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::VulnerabilityScanning]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        Ok(check_tool_availability("x8").await)
    }

    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        info!("X8Scanner: scanning target {}", target.host);
        
        if !self.check_dependencies().await.unwrap_or(false) {
            warn!("X8Scanner: x8 binary not found. Skipping.");
            return Ok(Vec::new());
        }

        let mut findings = Vec::new();

        let url = if target.host.starts_with("http") {
            target.host.clone()
        } else {
            format!("http://{}", target.host)
        };

        let temp = match tempfile::NamedTempFile::new() {
            Ok(t) => t,
            Err(e) => {
                error!("X8Scanner: failed to create temp file: {}", e);
                return Ok(findings);
            }
        };
        let temp_path = temp.path().to_string_lossy().to_string();

        let _output = tokio::time::timeout(std::time::Duration::from_secs(180), Command::new(&self.binary_path)
            .arg("-u")
            .arg(&url)
            .arg("-oJ")
            .arg(&temp_path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output())
            .await
            .context("X8 execution timed out")?
            .context("Failed to run x8")?;

        if let Ok(content) = tokio::fs::read_to_string(&temp_path).await {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
                // x8 output is often a JSON array of findings
                if let Some(params) = json.as_array() {
                    if !params.is_empty() {
                        findings.push(Finding::new(
                            FINDING_HIDDEN_PARAMS,
                            Category::Vulnerability,
                            Severity::Info,
                            &format!("Discovered {} hidden parameters on {}", params.len(), url),
                            serde_json::json!({
                                "url": url,
                                "parameters": params,
                            })
                        ));
                    }
                }
            }
        }

        Ok(findings)
    }
}
