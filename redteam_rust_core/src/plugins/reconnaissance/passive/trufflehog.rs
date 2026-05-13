use crate::plugins::{ScannerPlugin, Capability};
use crate::models::{TargetHost, Finding, Severity, Category};
use crate::utils::tool_detection::detect_tool;
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::info;
use std::process::Stdio;
use tokio::process::Command;

pub struct TruffleHogScanner {
    binary_path: String,
}

impl Default for TruffleHogScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl TruffleHogScanner {
    pub fn new() -> Self {
        let path = detect_tool("trufflehog");
        Self {
            binary_path: path,
        }
    }
}

#[async_trait]
impl ScannerPlugin for TruffleHogScanner {
    fn name(&self) -> &'static str {
        crate::models::PLUGIN_TRUFFLEHOG
    }

    
        fn metadata(&self) -> crate::plugins::PluginMetadata {
        crate::plugins::PluginMetadata {
            name: self.name().to_string(),
            description: "Automated security analysis using this plugin.".to_string(),
            target_type: crate::plugins::TargetType::Host,
            risk_level: crate::plugins::RiskLevel::Medium,
            layer: crate::core::capability_layer::ScanLayer::Passive,
            expected_duration: std::time::Duration::from_secs(300),
            capabilities: self.capabilities(),
            cost: 5,
            category: "Reconnaissance".to_string(),
            mitre_attacks: vec![],
            exploit_difficulty: crate::plugins::RiskLevel::Medium,
            blackarch_category: None,
            is_destructive: false,
            poc_mode: false, ..Default::default() }
    }
    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::SecretDiscovery]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability("trufflehog").await)
    }


    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        info!("TruffleHogScanner: scanning for secrets on {}", target.host);

        // TruffleHog can scan many sources. For a generic target, we'll try 'filesystem' (if local)
        // or potentially 'github' if the target looks like a repo URL.
        // For now, let's implement a generic web-secret scan if it looks like a URL.
        
        let child = if target.host.starts_with("http") {
             Command::new(&self.binary_path)
                .arg("github") // Use github scan as a proxy for "remote scan" if it's a repo, or 'git'
                .arg("--repo").arg(&target.host)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .context("Failed to spawn trufflehog")?
        } else {
            // Assume filesystem if not a URL
            Command::new(&self.binary_path)
                .arg("filesystem")
                .arg(&target.host)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .context("Failed to spawn trufflehog")?
        };

        let output = child.wait_with_output().await.context("Failed to wait for trufflehog")?;

        let mut findings = Vec::new();
        let content = String::from_utf8_lossy(&output.stdout);
        
        // TruffleHog usually outputs JSON if --json is passed, but here we process standard output
        // for "Found secret" indicators.
        for line in content.lines() {
            if line.to_lowercase().contains("found secret") || line.contains("Detector Type") {
                findings.push(Finding::new(
                    "SECRET-LEAK",
                    Category::CredentialLeak,
                    Severity::Critical,
                    &format!("Potential secret/credential leak found on {}.", target.host),
                    serde_json::json!({ "raw_match": line.trim() })
                ).with_tactical_path("Revoke the compromised credential and remove it from the source."));
            }
        }

        Ok(findings)
    }
}
