use crate::plugins::{ScannerPlugin, Capability, PluginMetadata, RiskLevel};
use crate::models::{TargetHost, Finding, Severity, Category, TargetType, PLUGIN_CRLF};
use crate::utils::tool_detection::detect_tool;
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::info;
use std::process::Stdio;
use tokio::process::Command;


pub struct CRLFScanner {
    binary_path: String,
}

impl Default for CRLFScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl CRLFScanner {
    pub fn new() -> Self {
        let path = detect_tool("crlfuzz");
        Self {
            binary_path: path,
        }
    }
}

#[async_trait]
impl ScannerPlugin for CRLFScanner {
    fn name(&self) -> &'static str {
        PLUGIN_CRLF
    }

    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: self.name().to_string(),
            description: "Fast tool for CRLF injection vulnerability scanning.".to_string(),
            target_type: TargetType::Web,
            risk_level: RiskLevel::Low,
            layer: crate::core::capability_layer::ScanLayer::Scanning,
            expected_duration: std::time::Duration::from_secs(120),
            capabilities: self.capabilities(),
            cost: 3,
            category: "Enumeration".to_string(),
            mitre_attacks: vec![],
            exploit_difficulty: crate::plugins::RiskLevel::Medium,
            blackarch_category: None,
            is_destructive: false,
            poc_mode: false, ..Default::default() }
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::VulnerabilityScanning, Capability::WebFuzzing]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability("crlfuzz").await)
    }

    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        info!("CRLFScanner: launching scan against {}", target.host);

        // CRLFuzz expects a URL.
        let url = if target.host.starts_with("http") {
            target.host.clone()
        } else {
            format!("http://{}", target.host)
        };

        let mut cmd = Command::new(&self.binary_path);
        cmd.arg("-u").arg(&url)
           .arg("-s") // silent
           .stdin(Stdio::null())
           .stdout(Stdio::piped())
           .stderr(Stdio::null());

        let output = cmd.output().await.context("Failed to execute crlfuzz")?;

        let mut findings = Vec::new();

        // CRLFuzz outputs vulnerable URLs to stdout if found.
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if line.trim().is_empty() { continue; }
            
            findings.push(Finding::new(
                crate::models::FINDING_CRLF_INJECTION,
                Category::Vulnerability,
                Severity::Medium,
                &format!("Possible CRLF injection vulnerability found at {}", line),
                serde_json::json!({
                    "url": line,
                    "type": "CRLF Injection",
                    "payload": "Various (detected by crlfuzz)"
                })
            ).with_tactical_path("Sanitize user input and headers to prevent injection of carriage return and line feed characters."));
        }

        Ok(findings)
    }
}
