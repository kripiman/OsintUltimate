// src/plugins/reconnaissance/passive/waymore.rs
// 🔧 Waymore: URL discovery from multiple archive sources
// ⚡ Async wrapper for waymore (successor to waybackurls/gau)

use crate::plugins::{ScannerPlugin, Capability, PluginMetadata, TargetType, RiskLevel};
use crate::models::{TargetHost, Finding, Severity, Category, PLUGIN_WAYMORE, FINDING_WAYMORE_URL};
use crate::utils::tool_detection::detect_tool;
use async_trait::async_trait;
use anyhow::Result;
use tracing::{info, warn};
use std::process::Stdio;
use tokio::process::Command;
use std::time::Duration;

pub struct WaymoreScanner {
    binary_path: String,
}

impl Default for WaymoreScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl WaymoreScanner {
    pub fn new() -> Self {
        let path = detect_tool("waymore");
        Self {
            binary_path: path,
        }
    }
}

#[async_trait]
impl ScannerPlugin for WaymoreScanner {
    fn name(&self) -> &'static str {
        PLUGIN_WAYMORE
    }

    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: self.name().to_string(),
            description: "Fetches historical URLs from Wayback Machine, Common Crawl, AlienVault OTX, URLScan, and more. Optimized for speed and coverage.".to_string(),
            target_type: TargetType::Web,
            risk_level: RiskLevel::Safe,
            layer: crate::core::capability_layer::ScanLayer::Passive,
            expected_duration: Duration::from_secs(300), // Can be slow for large domains
            capabilities: vec![Capability::HistoricalRecon, Capability::OsintDiscovery],
            cost: 4,
            category: "Reconnaissance".to_string(),
            mitre_attacks: vec!["T1594".to_string()], // Search Victim-Owned Websites
            exploit_difficulty: RiskLevel::Low,
            blackarch_category: Some("recon".to_string()),
            is_destructive: false,
            poc_mode: true, ..Default::default() }
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::HistoricalRecon, Capability::OsintDiscovery]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability("waymore").await)
    }

    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        info!("🔍 WAYMORE: Fetching historical endpoints for {}", target.host);
        let mut findings = Vec::new();

        // Run waymore to get URLs
        // -n: don't download files, just get URLs
        // -mode U: URL mode
        // -oU: output URLs file
        
        let output = match tokio::time::timeout(
            Duration::from_secs(300),
            Command::new(&self.binary_path)
                .arg("-i")
                .arg(&target.host)
                .arg("-mode")
                .arg("U") // URL search mode
                .arg("-n") // No downloading of archived responses
                .arg("-oU")
                .arg("-") // Output to stdout
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .output()
        ).await {
            Ok(Ok(o)) => o,
            _ => {
                warn!("⚠️ WAYMORE: Execution failed or timed out for {}", target.host);
                return Ok(findings);
            }
        };

        let content = String::from_utf8_lossy(&output.stdout);
        let urls: Vec<String> = content.lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();

        if !urls.is_empty() {
            findings.push(Finding::new(
                FINDING_WAYMORE_URL,
                Category::Recon,
                Severity::Info,
                &format!("Discovered {} historical endpoints via Waymore for {}", urls.len(), target.host),
                serde_json::json!({
                    "count": urls.len(),
                    "sample": urls.iter().take(20).collect::<Vec<_>>(),
                    "urls": urls, // Complete list for downstream consumption
                })
            ).with_blackarch_category("recon"));
        }

        Ok(findings)
    }
}
