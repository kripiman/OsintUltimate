use crate::plugins::{ScannerPlugin, Capability};
use crate::models::{TargetHost, Finding, Severity, Category};
use crate::utils::tool_detection::detect_tool;
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::info;
use std::process::Stdio;
use tokio::process::Command;
pub struct FeroxbusterScanner {
    binary_path: String,
}
impl Default for FeroxbusterScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl FeroxbusterScanner {
    pub fn new() -> Self {
        let path = detect_tool("feroxbuster");
        Self {
            binary_path: path,
        }
    }
}
#[async_trait]
impl ScannerPlugin for FeroxbusterScanner {
    fn name(&self) -> &'static str {
        "feroxbuster"
    }
        fn metadata(&self) -> crate::plugins::PluginMetadata {
        crate::plugins::PluginMetadata {
            name: self.name().to_string(),
            description: "Automated security analysis using this plugin.".to_string(),
            target_type: crate::plugins::TargetType::Host,
            risk_level: crate::plugins::RiskLevel::Medium,
            layer: crate::core::capability_layer::ScanLayer::Scanning,
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
        vec![Capability::WebFuzzing]
    }
    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability("feroxbuster").await)
    }
    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        info!("FeroxbusterScanner: searching for hidden content on {}", target.host);
        // feroxbuster execution
        // -u: target URL
        // -q: quiet mode
        // -n: no recursion (optional, but let's keep it professional and recursive by default if not specified)
        // For professional use, we might want to limit depth or use a specific wordlist.
        let child = Command::new(&self.binary_path)
            .arg("-u")
            .arg(&target.host)
            .arg("--quiet")
            .arg("--no-state") // Don't create .state files
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .context("Failed to spawn feroxbuster")?;
        let output = child.wait_with_output().await.context("Failed to wait for feroxbuster")?;
        let mut findings = Vec::new();
        let content = String::from_utf8_lossy(&output.stdout);
        for line in content.lines() {
            if line.is_empty() { continue; }
            // Feroxbuster output usually contains status code and URL
            findings.push(Finding::new(
                "FEROXBUSTER-DISCOVERY",
                Category::Recon,
                Severity::Info,
                &format!("Discovered path via feroxbuster: {}", line),
                serde_json::json!({ "output": line.trim() })
            ).with_tactical_path("Review the discovered path for sensitive information or unauthorized access."));
        }
        Ok(findings)
    }
}
