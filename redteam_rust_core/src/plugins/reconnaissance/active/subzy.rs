use crate::plugins::{ScannerPlugin, Capability, TargetType, RiskLevel};
use crate::models::{TargetHost, Finding, Severity, Category};
use crate::utils::{detect_tool, check_tool_availability};
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::{info, warn, error};
use std::process::Stdio;
use tokio::process::Command;
use crate::models::constants::*;
use std::io::Write;

pub struct SubzyScanner {
    binary_path: String,
}

impl Default for SubzyScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl SubzyScanner {
    pub fn new() -> Self {
        let path = detect_tool("subzy");
        Self {
            binary_path: path,
        }
    }
}

#[async_trait]
impl ScannerPlugin for SubzyScanner {
    fn name(&self) -> &'static str {
        PLUGIN_SUBZY
    }

    fn metadata(&self) -> crate::plugins::PluginMetadata {
        crate::plugins::PluginMetadata {
            name: self.name().to_string(),
            description: "Dedicated subdomain takeover detector with 60+ fingerprints.".to_string(),
            target_type: TargetType::Host,
            risk_level: RiskLevel::Low,
            layer: crate::core::capability_layer::ScanLayer::Discovery,
            expected_duration: std::time::Duration::from_secs(30),
            capabilities: vec![Capability::VulnerabilityScanning, Capability::SubdomainEnumeration],
            cost: 2,
            category: "Reconnaissance".to_string(),
            mitre_attacks: vec!["T1583.001".to_string()],
            exploit_difficulty: RiskLevel::Low,
            blackarch_category: Some("recon".to_string()),
            is_destructive: false,
            poc_mode: true, ..Default::default() }
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::VulnerabilityScanning, Capability::SubdomainEnumeration]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        Ok(check_tool_availability("subzy").await)
    }

    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        info!("SubzyScanner: checking for takeover on {}", target.host);
        
        if !self.check_dependencies().await.unwrap_or(false) {
            warn!("SubzyScanner: subzy binary not found. Skipping.");
            return Ok(Vec::new());
        }

        let mut findings = Vec::new();

        let mut temp = match tempfile::NamedTempFile::new() {
            Ok(t) => t,
            Err(e) => {
                error!("SubzyScanner: failed to create temp file: {}", e);
                return Ok(findings);
            }
        };
        
        if let Err(e) = writeln!(temp, "{}", target.host) {
            error!("SubzyScanner: failed to write to temp file: {}", e);
            return Ok(findings);
        }
        
        let temp_path = temp.path().to_string_lossy().to_string();

        let output = tokio::time::timeout(std::time::Duration::from_secs(60), Command::new(&self.binary_path)
            .arg("run")
            .arg("--targets")
            .arg(&temp_path)
            .arg("--hide_fails")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output())
            .await
            .context("Subzy execution timed out")?
            .context("Failed to run subzy")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        // subzy output for vulnerable: [VULNERABLE] target.com [Service Name]
        for line in stdout.lines() {
            if line.contains("VULNERABLE") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                let service = if parts.len() >= 3 {
                    parts[2..].join(" ").trim_matches(|c| c == '[' || c == ']').to_string()
                } else {
                    "Unknown Service".to_string()
                };
                
                findings.push(Finding::new(
                    FINDING_SUBDOMAIN_TAKEOVER,
                    Category::Vulnerability,
                    Severity::High,
                    &format!("Potential subdomain takeover detected on {} via {}", target.host, service),
                    serde_json::json!({
                        "host": target.host,
                        "service": service,
                        "raw_output": line,
                    })
                ));
            }
        }

        Ok(findings)
    }
}
