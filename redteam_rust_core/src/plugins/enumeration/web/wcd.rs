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

pub struct WcdScanner {
    binary_path: String,
}

impl Default for WcdScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl WcdScanner {
    pub fn new() -> Self {
        // We'll use httpx as a backend for header analysis
        let path = detect_tool("httpx");
        Self {
            binary_path: path,
        }
    }
}

#[async_trait]
impl ScannerPlugin for WcdScanner {
    fn name(&self) -> &'static str {
        PLUGIN_WCD
    }

    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: self.name().to_string(),
            description: "Scanner for Web Cache Deception vulnerabilities. Identifies sensitive data leakage via cache-poisoned static extensions.".to_string(),
            target_type: TargetType::Web,
            risk_level: RiskLevel::Low,
            layer: ScanLayer::Scanning,
            category: "Web".to_string(),
            expected_duration: std::time::Duration::from_secs(60),
            capabilities: vec![Capability::VulnerabilityScanning],
            cost: 2,
            mitre_attacks: vec!["T1595.002".to_string()],
            exploit_difficulty: RiskLevel::Medium,
            blackarch_category: Some("webapp".to_string()),
            is_destructive: false,
            poc_mode: true, ..Default::default() }
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::VulnerabilityScanning]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability("httpx").await)
    }

    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        info!("WcdScanner: scanning {}", target.host);
        
        if !self.check_dependencies().await.unwrap_or(false) {
            warn!("WcdScanner: httpx required for WCD scanning. Skipping.");
            return Ok(Vec::new());
        }

        let mut findings = Vec::new();
        let base_url = if target.host.starts_with("http") {
            target.host.clone()
        } else {
            format!("https://{}", target.host)
        };

        // 1. Identify sensitive paths to probe
        let mut paths_to_probe = vec![
            "/".to_string(),
            "/home".to_string(),
            "/dashboard".to_string(),
            "/api/v1/user".to_string(),
            "/profile".to_string(),
            "/settings".to_string(),
            "/account".to_string(),
        ];

        for f in target.findings.iter() {
             if let Some(ev) = &f.evidence.primary {
                 if let Some(path) = ev.data.get("path").and_then(|v| v.as_str()) {
                     if !path.contains(".") && path.len() > 1 { paths_to_probe.push(path.to_string()); }
                 }
             }
        }
        paths_to_probe.sort();
        paths_to_probe.dedup();

        // 2. Perform probing with static extensions
        let extensions = [".css", ".jpg", ".js", ".v14"];
        
        for path in paths_to_probe.into_iter().take(15) {
            let normalized_path = if path.starts_with('/') { path } else { format!("/{}", path) };
            let target_path = format!("{}{}", base_url.trim_end_matches('/'), normalized_path);
            
            for ext in &extensions {
                let probe_url = format!("{}{}", target_path, ext);
                
                let output_res = tokio::time::timeout(
                    std::time::Duration::from_secs(10),
                    Command::new(&self.binary_path)
                        .args(["-u", &probe_url, "-silent", "-status-code", "-include-response-headers"])
                        .stdin(Stdio::null())
                        .stdout(Stdio::piped())
                        .stderr(Stdio::null())
                        .output(),
                ).await;

                let output = match output_res {
                    Ok(Ok(o)) => o,
                    Ok(Err(e)) => { warn!("WcdScanner: httpx error for {}: {}", probe_url, e); continue; }
                    Err(_) => { warn!("WcdScanner: timeout for {}", probe_url); continue; }
                };

                if output.status.success() {
                    let stdout = String::from_utf8_lossy(&output.stdout);

                    // HIT is unambiguous: CDN/proxy confirmed cached response for this URL
                    if stdout.contains("200") && stdout.contains("HIT") {
                        findings.push(Finding::new(
                            FINDING_WEB_CACHE_DECEPTION,
                            Category::Vulnerability,
                            Severity::Medium,
                            &format!("Potential Web Cache Deception at {}", probe_url),
                            serde_json::json!({
                                "url": probe_url,
                                "evidence_headers": stdout.trim(),
                            })
                        ).with_tactical_path("Verify if authenticated sensitive data is cached when accessed with static extensions. This could lead to account takeover or PII leakage via shared caches (CDN)."));
                        break; 
                    }
                }
            }
        }

        Ok(findings)
    }
}
