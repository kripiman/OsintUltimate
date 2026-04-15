use crate::plugins::{DiscoveryPlugin, Capability};
use crate::models::TargetHost;
use crate::utils::tool_detection::detect_tool;
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::{info, warn};
use std::process::Stdio;

pub struct SubfinderScanner {
    binary_path: String,
}

impl SubfinderScanner {
    pub fn new() -> Self {
        let path = detect_tool("subfinder");
        Self {
            binary_path: path,
        }
    }
}

#[async_trait]
impl DiscoveryPlugin for SubfinderScanner {
    fn name(&self) -> &'static str {
        crate::models::PLUGIN_SUBFINDER
    }

        fn metadata(&self) -> crate::plugins::PluginMetadata {
        crate::plugins::PluginMetadata {
            name: self.name().to_string(),
            description: "Subfinder: Subdomain discovery tool (Emergency Fallback for Sovereign Recon).".to_string(),
            target_type: crate::plugins::TargetType::Osint,
            risk_level: crate::plugins::RiskLevel::Safe,
            layer: crate::core::capability_layer::ScanLayer::Passive,
            expected_duration: std::time::Duration::from_secs(300),
            capabilities: self.capabilities(),
            cost: 5,
            category: "Reconnaissance".to_string(),
            mitre_attacks: vec![],
            remediation_difficulty: crate::plugins::RiskLevel::Medium,
            blackarch_category: None,
            is_destructive: false,
            poc_mode: false,
        }
    }
    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::SubdomainEnumeration]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability("subfinder").await)
    }


    async fn discover(&self, target: &TargetHost) -> Result<Vec<String>> {
        info!("SubfinderScanner: launching discovery against {}", target.host);

        let temp_file = tempfile::NamedTempFile::new().context("Failed to create temp file for Subfinder")?;
        let temp_path = temp_file.path().to_string_lossy().to_string();

        let mut child = crate::utils::common::stealth_command(&self.binary_path)
            .arg("-d").arg(&target.host)
            .arg("-silent")
            .arg("-o").arg(&temp_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("Failed to spawn subfinder")?;

        let status = child.wait().await.context("Failed to wait for subfinder")?;

        if !status.success() {
            warn!("Subfinder failed on {}", target.host);
        }

        let mut discovered = Vec::new();

        // RAM-FIX: Read line-by-line to avoid loading massive files (e.g. 100k subdomains) into memory at once
        if let Ok(file) = tokio::fs::File::open(&temp_path).await {
            use tokio::io::{AsyncBufReadExt, BufReader};
            let mut lines = BufReader::new(file).lines();
            while let Some(line) = lines.next_line().await? {
                let domain = line.trim().to_string();
                if !domain.is_empty() {
                    discovered.push(domain);
                }
            }
        }

        Ok(discovered)
    }
}
