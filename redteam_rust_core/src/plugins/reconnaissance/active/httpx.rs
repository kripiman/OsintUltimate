use crate::plugins::{ScannerPlugin, Capability};
use crate::models::{TargetHost, Finding, Severity, Category};
use crate::utils::tool_detection::detect_tool;
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::{info, warn};
use std::process::Stdio;
use tokio::process::Command;
pub struct HttpxScanner {
    binary_path: String,
}
impl HttpxScanner {
    pub fn new() -> Self {
        let path = detect_tool("httpx");
        Self {
            binary_path: path,
        }
    }
}
#[async_trait]
impl ScannerPlugin for HttpxScanner {
    fn name(&self) -> &'static str {
        crate::models::PLUGIN_HTTPX
    }
        fn metadata(&self) -> crate::plugins::PluginMetadata {
        crate::plugins::PluginMetadata {
            name: self.name().to_string(),
            description: "Automated security analysis using this plugin.".to_string(),
            target_type: crate::plugins::TargetType::Host,
            risk_level: crate::plugins::RiskLevel::Medium,
            layer: crate::core::capability_layer::ScanLayer::Discovery,
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
        vec![Capability::VulnerabilityScanning]
    }
    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability("httpx").await)
    }
    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        info!("HttpxScanner: probing HTTP for {}", target.host);
        
        // --- STEALTH-003: Using tactical command wrapper ---
        let mut child = crate::utils::common::stealth_command(&self.binary_path);
        child.arg("-u")
            .arg(&target.host)
            .arg("-title")
            .arg("-tech-detect")
            .arg("-status-code")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());

        let mut spawned = child.spawn().context("Failed to spawn httpx")?;
        
        let stdout = spawned.stdout.take().context("Failed to capture httpx stdout")?;
        use tokio::io::AsyncBufReadExt;
        let mut reader = tokio::io::BufReader::new(stdout).lines();
        
        let mut findings = Vec::new();
        
        // --- MEM-001: Streaming output processing instead of buffering entire output ---
        while let Some(line) = reader.next_line().await? {
            if !line.is_empty() {
                findings.push(Finding::new(
                    "HTTP-PROBE-SUCCESS",
                    Category::Recon,
                    Severity::Info,
                    &format!("HTTP-alive: {}", target.host),
                    serde_json::json!({ "output": line.trim() })
                ));
            }
        }

        // Wait for process to finish (kill_on_drop(true) in stealth_command handle reaping)
        let _ = spawned.wait().await?;
        
        Ok(findings)
    }
}
