use crate::plugins::{ScannerPlugin, Capability, PluginMetadata, RiskLevel, TargetType};
use crate::models::{TargetHost, Finding, Severity, Category};
use crate::core::capability_layer::ScanLayer;
use crate::utils::tool_detection::detect_tool;
use async_trait::async_trait;
use anyhow::Result;
use tracing::{info, warn};
use tokio::process::Command;
use std::process::Stdio;
use crate::models::constants::*;

pub struct PpmapScanner {
    binary_path: String,
}

impl Default for PpmapScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl PpmapScanner {
    pub fn new() -> Self {
        let path = detect_tool("ppmap");
        Self {
            binary_path: path,
        }
    }
}

#[async_trait]
impl ScannerPlugin for PpmapScanner {
    fn name(&self) -> &'static str {
        PLUGIN_PPMAP
    }

    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: self.name().to_string(),
            description: "Scanner for Prototype Pollution vulnerabilities (Client-side & Server-side).".to_string(),
            target_type: TargetType::Web,
            risk_level: RiskLevel::Medium,
            layer: ScanLayer::Scanning,
            category: "Web".to_string(),
            expected_duration: std::time::Duration::from_secs(60),
            capabilities: vec![Capability::VulnerabilityScanning, Capability::ApiSecurity],
            cost: 2,
            mitre_attacks: vec!["T1595.002".to_string()],
            exploit_difficulty: RiskLevel::Low,
            blackarch_category: Some("webapp".to_string()),
            is_destructive: false,
            poc_mode: true, ..Default::default() }
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::VulnerabilityScanning, Capability::ApiSecurity]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability("ppmap").await)
    }

    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        info!("PpmapScanner: scanning {}", target.host);
        
        if !self.check_dependencies().await.unwrap_or(false) {
            warn!("PpmapScanner: ppmap binary not found. Skipping.");
            return Ok(Vec::new());
        }

        let mut findings = Vec::new();
        
        // 1. Gather URLs to test
        let mut urls_to_test = std::collections::HashSet::new();
        
        // Add host itself
        let base_url = if target.host.starts_with("http") {
            target.host.clone()
        } else {
            format!("https://{}", target.host)
        };
        urls_to_test.insert(base_url);

        for f in target.findings.iter() {
             if let Some(ev) = &f.evidence.primary {
                 for key in ["urls", "discovered_endpoints", "url", "uri", "endpoint"] {
                    if let Some(val) = ev.data.get(key) {
                        if let Some(s) = val.as_str() {
                            if s.starts_with("http") { urls_to_test.insert(s.to_string()); }
                        } else if let Some(arr) = val.as_array() {
                            for item in arr {
                                if let Some(s) = item.as_str() {
                                    if s.starts_with("http") { urls_to_test.insert(s.to_string()); }
                                }
                            }
                        }
                    }
                 }
             }
        }

        // 2. Prioritize and limit URLs (cap at 50 to avoid pipeline stall)
        let mut sorted_urls: Vec<_> = urls_to_test.into_iter().collect();
        sorted_urls.sort_by_key(|u| {
            // Prioritize JS files and URLs with parameters
            let lower = u.to_lowercase();
            if lower.ends_with(".js") || lower.contains(".js?") || lower.contains("?") { 0 } else { 1 }
        });

        for url in sorted_urls.into_iter().take(50) {
            info!("PpmapScanner: testing {}", url);

            let output_res = tokio::time::timeout(
                std::time::Duration::from_secs(60),
                Command::new(&self.binary_path)
                    .arg("-u")
                    .arg(&url)
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .output()
            ).await;

            match output_res {
                Ok(Ok(output)) => {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    // ppmap success indicator: usually mentions "VULNERABLE" or shows the payload
                    if stdout.contains("VULNERABLE") || stdout.contains("constructor.prototype") {
                         findings.push(Finding::new(
                            FINDING_PROTOTYPE_POLLUTION,
                            Category::Vulnerability,
                            Severity::High,
                            &format!("Prototype Pollution found at {}", url),
                            serde_json::json!({
                                "url": url,
                                "raw_output": stdout.chars().take(1000).collect::<String>(),
                            })
                        ).with_tactical_path("Verify if this can be chained to XSS or bypass filters. Sanitize input to prevent prototype poisoning. Check for server-side pollution if this is a Node.js target."));
                    }
                },
                Ok(Err(e)) => warn!("PpmapScanner error for {}: {}", url, e),
                Err(_) => warn!("PpmapScanner timeout for {}", url),
            }
        }

        Ok(findings)
    }
}
