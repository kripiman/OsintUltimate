use crate::plugins::{ScannerPlugin, Capability};
use crate::models::{TargetHost, Finding, Severity, Category};
use crate::utils::tool_detection::detect_tool;
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::info;
use std::process::Stdio;
use tokio::process::Command;
pub struct CloudEnumScanner {
    binary_path: String,
}
impl Default for CloudEnumScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl CloudEnumScanner {
    pub fn new() -> Self {
        let path = detect_tool("cloud_enum");
        Self {
            binary_path: path,
        }
    }
}
#[async_trait]
impl ScannerPlugin for CloudEnumScanner {
    fn name(&self) -> &'static str {
        crate::models::PLUGIN_CLOUD_ENUM
    }
        fn metadata(&self) -> crate::plugins::PluginMetadata {
        crate::plugins::PluginMetadata {
            name: self.name().to_string(),
            description: "Automated security analysis using this plugin.".to_string(),
            target_type: crate::plugins::TargetType::Cloud,
            risk_level: crate::plugins::RiskLevel::Medium,
            layer: crate::core::capability_layer::ScanLayer::Passive,
            expected_duration: std::time::Duration::from_secs(300),
            capabilities: self.capabilities(),
            cost: 5,
            category: "Enumeration".to_string(),
            mitre_attacks: vec![],
            exploit_difficulty: crate::plugins::RiskLevel::Medium,
            blackarch_category: None,
            is_destructive: false,
            poc_mode: false, ..Default::default() }
    }
    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::CloudAudit]
    }
    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability("cloudenum").await)
    }
    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        info!("CloudEnumScanner: enumerating cloud assets for {}", target.host);
        // CloudEnum execution
        let child = Command::new(&self.binary_path)
            .arg("-k")
            .arg(&target.host)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .context("Failed to spawn cloud_enum")?;
        let output = child.wait_with_output().await.context("Failed to wait for CloudEnum")?;
        let mut findings = Vec::new();
        let content = String::from_utf8_lossy(&output.stdout);
        if content.contains("Found") || content.contains("http") {
            findings.push(Finding::new(
                "CLOUD-ASSET-DISCOVERED",
                Category::ExposedAsset,
                Severity::Info,
                &format!("Public cloud assets discovered for {} via CloudEnum.", target.host),
                serde_json::json!({ "output": content.trim() })
            ));
        }
        Ok(findings)
    }
}
