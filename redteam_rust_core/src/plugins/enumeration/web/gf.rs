use crate::plugins::{ScannerPlugin, Capability, PluginMetadata, RiskLevel};
use crate::models::{TargetHost, Finding, Severity, Category, TargetType, PLUGIN_GF, FINDING_GF_PATTERN};
use crate::utils::tool_detection::detect_tool;
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::info;
use std::process::Stdio;
use tokio::process::Command;

pub struct GfScanner {
    binary_path: String,
}

impl Default for GfScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl GfScanner {
    pub fn new() -> Self {
        let path = detect_tool("gf");
        Self {
            binary_path: path,
        }
    }
}

#[async_trait]
impl ScannerPlugin for GfScanner {
    fn name(&self) -> &'static str {
        PLUGIN_GF
    }

    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: self.name().to_string(),
            description: "Grep-based pattern discovery for security audits (SSRF, LFI, RCE, Credentials).".to_string(),
            target_type: TargetType::Web,
            risk_level: RiskLevel::Safe,
            layer: crate::core::capability_layer::ScanLayer::Scanning,
            expected_duration: std::time::Duration::from_secs(30),
            capabilities: self.capabilities(),
            cost: 1,
            category: "Enumeration".to_string(),
            mitre_attacks: vec![],
            exploit_difficulty: crate::plugins::RiskLevel::Medium,
            blackarch_category: None,
            is_destructive: false,
            poc_mode: false, ..Default::default() }
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::SecurityAuditing, Capability::OsintDiscovery]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability("gf").await)
    }

    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        info!("GfScanner: searching patterns for {}", target.host);

        // Gf usually works on files or stdin.
        // For professional reconnaissance, we'll scan various patterns if they are available.
        let patterns = vec!["ssrf".to_string(), "sqli".to_string(), "lfi".to_string(), "rce".to_string(), "debug-pages".to_string(), "idors".to_string(), "interestingparams".to_string()];
        let mut findings = Vec::new();

        for pattern in patterns {
            // In a real scenario, we might have a file of URLs gathered by Gau/Wayback.
            // For now, we'll simulate the execution. If we had a discovery-aggregator, we'd use it.
            // Professional approach: gf is better used as a post-discovery hook.
            // Here we just implement the wrapper.
            
            let mut cmd = Command::new(&self.binary_path);
            cmd.arg(&pattern)
               .stdin(Stdio::null())
               .stdout(Stdio::piped())
               .stderr(Stdio::null());

            // Since we don't have a "gathered_urls" file yet in this context, 
            // the plugin will be safe but potentially empty until discovery runs.
            let output = cmd.output().await.context("Failed to execute gf")?;
            
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if line.trim().is_empty() { continue; }
                
                findings.push(Finding::new(
                    FINDING_GF_PATTERN,
                    Category::Recon,
                    Severity::Info,
                    &format!("Interesting pattern '{}' found: {}", pattern, line),
                    serde_json::json!({
                        "pattern": pattern.clone(),
                        "line": line
                    })
                ));
            }
        }

        Ok(findings)
    }
}
