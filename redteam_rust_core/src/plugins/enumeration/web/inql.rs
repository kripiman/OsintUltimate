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
use std::collections::HashSet;

pub struct InQLScanner {
    binary_path: String,
}

impl Default for InQLScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl InQLScanner {
    pub fn new() -> Self {
        let path = detect_tool("inql");
        Self {
            binary_path: path,
        }
    }
}

#[async_trait]
impl ScannerPlugin for InQLScanner {
    fn name(&self) -> &'static str {
        PLUGIN_INQL
    }

    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: self.name().to_string(),
            description: "GraphQL introspection and analysis tool. Extracted schemas for deep API testing.".to_string(),
            target_type: TargetType::Web,
            risk_level: RiskLevel::Safe,
            layer: ScanLayer::Scanning,
            category: "Web/API".to_string(),
            expected_duration: std::time::Duration::from_secs(45),
            capabilities: vec![Capability::GraphQL, Capability::ApiSecurity],
            cost: 2,
            mitre_attacks: vec!["T1595.002".to_string()],
            exploit_difficulty: RiskLevel::Low,
            blackarch_category: Some("webapp".to_string()),
            is_destructive: false,
            poc_mode: true, ..Default::default() }
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::GraphQL, Capability::ApiSecurity]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability("inql").await)
    }

    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        info!("InQLScanner: scanning {}", target.host);
        
        // 0. Fail-closed if binary missing
        if !self.check_dependencies().await.unwrap_or(false) {
            warn!("InQLScanner: inql binary not found. Skipping.");
            return Ok(Vec::new());
        }

        let mut findings = Vec::new();
        
        // 1. Identify GraphQL endpoints from previous findings or defaults
        let mut endpoints = vec!["/graphql".to_string(), "/gql".to_string(), "/api/graphql".to_string()];
        
        for f in target.findings.iter() {
             if let Some(ev) = &f.evidence.primary {
                 // Check common keys from Katana, Jsluice, etc.
                 for key in ["urls", "discovered_endpoints", "url", "uri", "endpoint", "path"] {
                    if let Some(val) = ev.data.get(key) {
                        if let Some(s) = val.as_str() {
                            if is_graphql_candidate(s) { endpoints.push(s.to_string()); }
                        } else if let Some(arr) = val.as_array() {
                            for item in arr {
                                if let Some(s) = item.as_str() {
                                    if is_graphql_candidate(s) { endpoints.push(s.to_string()); }
                                }
                            }
                        }
                    }
                 }
             }
        }
        
        // Add host itself if it's a candidate
        if is_graphql_candidate(&target.host) {
            endpoints.push(target.host.clone());
        }

        endpoints.sort();
        endpoints.dedup();
        
        // Final sanity check: remove duplicate paths if they differ only by protocol/slashes
        let mut final_endpoints = Vec::new();
        let mut seen_paths = HashSet::new();
        for e in endpoints {
            let path = e.trim_start_matches("http://")
                        .trim_start_matches("https://")
                        .trim_end_matches('/');
            if seen_paths.insert(path.to_string()) {
                final_endpoints.push(e);
            }
        }
        let endpoints = final_endpoints;

        let base_url = if target.host.starts_with("http") {
            target.host.clone()
        } else {
            format!("https://{}", target.host)
        };

        for endpoint in endpoints {
            let target_url = if endpoint.starts_with("http") {
                endpoint
            } else {
                format!("{}{}", base_url.trim_end_matches('/'), if endpoint.starts_with('/') { endpoint } else { format!("/{}", endpoint) })
            };

            info!("InQLScanner: analyzing {}", target_url);

            let output_res = tokio::time::timeout(
                std::time::Duration::from_secs(30),
                Command::new(&self.binary_path)
                    .arg("-t")
                    .arg(&target_url)
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .output()
            ).await;

            match output_res {
                Ok(Ok(output)) => {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    
                    // InQL successful introspection indicators (v4/v5 precise check)
                    let stdout_lower = stdout.to_lowercase();
                    if output.status.success() && (stdout_lower.contains("introspection") || stdout_lower.contains("schema") || stdout_lower.contains("writing")) {
                         findings.push(Finding::new(
                            FINDING_GRAPHQL_INTROSPECTION,
                            Category::Recon,
                            Severity::Low,
                            &format!("GraphQL Introspection enabled at {}", target_url),
                            serde_json::json!({
                                "url": target_url,
                                "status": "Introspection Successful",
                                "output_summary": stdout.lines().take(5).collect::<Vec<_>>().join("\n"),
                            })
                        ).with_tactical_path("Disable introspection in production to prevent schema leakage. Use InQL or GraphQL-Cop for further mutation fuzzing."));
                    }
                },
                Ok(Err(e)) => warn!("InQLScanner error for {}: {}", target_url, e),
                Err(_) => warn!("InQLScanner timeout for {}", target_url),
            }
        }

        Ok(findings)
    }
}

fn is_graphql_candidate(s: &str) -> bool {
    let lower = s.to_lowercase();
    lower.contains("graphql") || lower.contains("gql") || lower.ends_with("/query")
}
