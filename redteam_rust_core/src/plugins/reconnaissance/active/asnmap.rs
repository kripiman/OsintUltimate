use crate::plugins::{DiscoveryPlugin, Capability, PluginMetadata, RiskLevel, TargetType, DiscoveryResult};
use crate::models::{TargetHost};
use crate::utils::tool_detection::detect_tool;
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::{info, warn};
use std::process::Stdio;

pub struct AsnmapScanner {
    binary_path: String,
}

impl Default for AsnmapScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl AsnmapScanner {
    pub fn new() -> Self {
        let path = detect_tool("asnmap");
        Self {
            binary_path: path,
        }
    }
}

#[async_trait]
impl DiscoveryPlugin for AsnmapScanner {
    fn name(&self) -> &'static str {
        crate::models::PLUGIN_ASNMAP
    }

    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: self.name().to_string(),
            description: "asnmap: ASN to IP/CIDR mapping tool.".to_string(),
            target_type: TargetType::Osint,
            risk_level: RiskLevel::Safe,
            layer: crate::core::capability_layer::ScanLayer::Passive,
            expected_duration: std::time::Duration::from_secs(60),
            capabilities: vec![Capability::AsnMapping],
            cost: 2,
            category: "Reconnaissance".to_string(),
            ..Default::default()
        }
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::AsnMapping]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability("asnmap").await)
    }

    async fn discover(&self, target: &TargetHost) -> Result<Vec<DiscoveryResult>> {
        info!("AsnmapScanner: launching mapping for {}", target.host);

        let child = tokio::process::Command::new(&self.binary_path)
            .arg("-a").arg(&target.host)
            .arg("-silent")
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .context("Failed to spawn asnmap")?;

        let output = child.wait_with_output().await?;
        if !output.status.success() {
            warn!("asnmap failed for {}", target.host);
            return Ok(Vec::new());
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut discovered = Vec::new();
        for line in stdout.lines() {
            let item = line.trim().to_string();
            if !item.is_empty() {
                discovered.push(DiscoveryResult { host: item, metadata: serde_json::json!({}) });
            }
        }

        Ok(discovered)
    }
}
