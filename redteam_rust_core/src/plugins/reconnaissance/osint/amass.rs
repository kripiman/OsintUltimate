use crate::plugins::{DiscoveryPlugin, Capability};
use crate::models::TargetHost;
use crate::utils::tool_detection::detect_tool;
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::{info, warn};
use std::process::Stdio;
use tokio::process::Command;

pub struct AmassScanner {
    binary_path: String,
}

impl AmassScanner {
    pub fn new() -> Self {
        let path = detect_tool("amass");
        Self {
            binary_path: path.to_string_lossy().to_string(),
        }
    }
}

#[async_trait]
impl DiscoveryPlugin for AmassScanner {
    fn name(&self) -> &'static str {
        crate::models::PLUGIN_AMASS
    }

    fn metadata(&self) -> crate::plugins::PluginMetadata {
        crate::plugins::PluginMetadata {
            name: self.name(),
            description: "Discovery of subdomains using passive OSINT techniques through Amass.",
            target_type: crate::plugins::TargetType::Osint,
            risk_level: crate::plugins::RiskLevel::Safe,
            layer: crate::core::capability_layer::ScanLayer::Passive,
            expected_duration: std::time::Duration::from_secs(60),
            capabilities: self.capabilities(),
            cost: 5,
            category: "Reconnaissance",
            mitre_attacks: vec![],
            remediation_difficulty: crate::plugins::RiskLevel::Medium,
        }
    }
    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::SubdomainEnumeration, Capability::OsintDiscovery]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability("amass").await)
    }


    async fn discover(&self, target: &TargetHost) -> Result<Vec<String>> {
        info!("AmassScanner: launching discovery against {}", target.host);

        // Amass 'enum' mode is standard for subdomain discovery
        let child = Command::new(&self.binary_path)
            .arg("enum")
            .arg("-d").arg(&target.host)
            .arg("-passive") // Passive for speed and stealth by default
            .arg("-silent")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .context("Failed to spawn amass")?;

        let output = child.wait_with_output().await.context("Failed to wait for amass")?;

        if !output.status.success() {
            warn!("Amass failed on {}", target.host);
        }

        let mut discovered = Vec::new();
        let content = String::from_utf8_lossy(&output.stdout);
        
        for line in content.lines() {
            let domain = line.trim().to_string();
            if !domain.is_empty() && domain.contains(&target.host) {
                discovered.push(domain);
            }
        }

        Ok(discovered)
    }
}
