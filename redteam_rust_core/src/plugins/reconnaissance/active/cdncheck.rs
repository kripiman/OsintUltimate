use crate::plugins::{ScannerPlugin, Capability, PluginMetadata, RiskLevel, TargetType};
use crate::models::{TargetHost, Finding, Category, Severity};
use crate::utils::tool_detection::detect_tool;
use async_trait::async_trait;
use anyhow::{Result, Context};
use std::process::Stdio;

pub struct CdnCheckScanner {
    binary_path: String,
}

impl Default for CdnCheckScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl CdnCheckScanner {
    pub fn new() -> Self {
        let path = detect_tool("cdncheck");
        Self {
            binary_path: path,
        }
    }

    pub async fn is_cdn(&self, target: &str) -> Result<bool> {
        let child = tokio::process::Command::new(&self.binary_path)
            .arg("-i").arg(target)
            .arg("-silent")
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .context("Failed to spawn cdncheck")?;

        let output = child.wait_with_output().await?;
        if !output.status.success() {
            return Ok(false);
        }

        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        // If cdncheck outputs the target, it means it IS a CDN IP
        Ok(!stdout.is_empty())
    }
}

#[async_trait]
impl ScannerPlugin for CdnCheckScanner {
    fn name(&self) -> &'static str {
        crate::models::PLUGIN_CDNCHECK
    }

    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: self.name().to_string(),
            description: "cdncheck: Detects if a target IP belongs to a CDN, Cloud or WAF provider.".to_string(),
            target_type: TargetType::Host,
            risk_level: RiskLevel::Safe,
            layer: crate::core::capability_layer::ScanLayer::Scanning,
            expected_duration: std::time::Duration::from_secs(5),
            capabilities: vec![Capability::CdnDetection],
            cost: 1,
            category: "Reconnaissance".to_string(),
            ..Default::default()
        }
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::CdnDetection]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability("cdncheck").await)
    }

    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        let addr = target.ip.as_deref().unwrap_or(&target.host);
        if self.is_cdn(addr).await? {
            return Ok(vec![
                Finding::builder(
                    "CDN-DETECTED",
                    Category::Recon,
                    Severity::Info,
                    &format!("Target {} is behind a CDN/Cloud provider", addr)
                ).build()
            ]);
        }
        Ok(Vec::new())
    }
}
