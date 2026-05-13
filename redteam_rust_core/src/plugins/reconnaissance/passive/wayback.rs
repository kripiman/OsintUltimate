use crate::plugins::{ScannerPlugin, Capability, PluginMetadata, TargetType, RiskLevel};
use crate::models::{TargetHost, Finding, Severity, Category, PLUGIN_WAYBACK};
use crate::utils::tool_detection::detect_tool;
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::info;
use std::process::Stdio;
use tokio::process::Command;
use std::time::Duration;
pub struct WaybackScanner {
    wayback_path: String,
    gau_path: String,
}
impl Default for WaybackScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl WaybackScanner {
    pub fn new() -> Self {
        let wayback_path = detect_tool("waybackurls");
        let gau_path = detect_tool("gau");
        Self {
            wayback_path,
            gau_path,
        }
    }
}
#[async_trait]
impl ScannerPlugin for WaybackScanner {
    fn name(&self) -> &'static str {
        PLUGIN_WAYBACK
    }
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: self.name().to_string(),
            description: "Fetches historical URLs from Wayback Machine, AlienVault, and Common Crawl using waybackurls and gau.".to_string(),
            target_type: TargetType::Web,
            risk_level: RiskLevel::Safe,
            layer: crate::core::capability_layer::ScanLayer::Passive,
            expected_duration: Duration::from_secs(60),
            capabilities: self.capabilities(),
            cost: 2,
            category: "Reconnaissance".to_string(),
            mitre_attacks: vec![],
            exploit_difficulty: crate::plugins::RiskLevel::Medium,
            blackarch_category: None,
            is_destructive: false,
            poc_mode: false, ..Default::default() }
    }
    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::HistoricalRecon, Capability::OsintDiscovery]
    }
    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability("waybackurls").await || crate::utils::check_tool_availability("gau").await)
    }
    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        info!("WaybackScanner: fetching historical URLs for {}", target.host);
        let mut findings = Vec::new();
        // Try gau first as it's often more comprehensive
        let binary = if crate::utils::check_tool_availability("gau").await {
            &self.gau_path
        } else {
            &self.wayback_path
        };
        let output = Command::new(binary)
            .arg(&target.host)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output()
            .await
            .context("Failed to execute historical URL tool")?;
        let content = String::from_utf8_lossy(&output.stdout);
        let urls: Vec<&str> = content.lines().collect();
        if !urls.is_empty() {
            findings.push(Finding::new(
                "HISTORICAL-URLS",
                Category::Recon,
                Severity::Info,
                &format!("Found {} historical URLs for {}", urls.len(), target.host),
                serde_json::json!({
                    "count": urls.len(),
                    "first_10": urls.iter().take(10).collect::<Vec<_>>()
                })
            ));
        }
        Ok(findings)
    }
}
