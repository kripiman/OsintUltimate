use crate::plugins::{ScannerPlugin, Capability};
use crate::models::{TargetHost, Finding, Severity, Category};
use crate::utils::tool_detection::detect_tool;
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::info;
use std::process::Stdio;
use tokio::process::Command;
pub struct SearchsploitScanner {
    binary_path: String,
}
impl Default for SearchsploitScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl SearchsploitScanner {
    pub fn new() -> Self {
        let path = detect_tool("searchsploit");
        Self {
            binary_path: path,
        }
    }
}
#[async_trait]
impl ScannerPlugin for SearchsploitScanner {
    fn name(&self) -> &'static str {
        "searchsploit"
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
            category: "Intelligence".to_string(),
            mitre_attacks: vec![],
            exploit_difficulty: crate::plugins::RiskLevel::Medium,
            blackarch_category: None,
            is_destructive: false,
            poc_mode: false, ..Default::default() }
    }
    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::VulnerabilityScanning]
    }
    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability("searchsploit").await)
    }
    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        // Searchsploit identifies exploits based on service versions found in other findings
        // We iterate through existing findings to find software versions
        for finding in target.findings.iter() {
            if finding.category == Category::TechnologyStack || finding.category == Category::Vulnerability {
                // Try to extract software name from description or evidence
                // This is a simplified heuristic
                let query: String = if let Some(product) = finding.evidence.primary
                    .as_ref()
                    .and_then(|e| e.data.get("product"))
                {
                    product.as_str().unwrap_or("").to_string()
                } else {
                    finding.core.description.clone()
                };
                if query.len() > 3 {
                    info!("SearchsploitScanner: searching exploits for '{}'", query);
                    let child = Command::new(&self.binary_path)
                        .arg("--json")
                        .arg(&query)
                        .stdin(Stdio::null())
                        .stdout(Stdio::piped())
                        .stderr(Stdio::null())
                        .spawn();
                    if let Ok(c) = child {
                        let output = c.wait_with_output().await.context("Failed to wait for searchsploit")?;
                        let content = String::from_utf8_lossy(&output.stdout);
                        if let Ok(json_data) = serde_json::from_str::<serde_json::Value>(&content) {
                            if let Some(results) = json_data.get("RESULTS_EXPLOIT") {
                                if results.as_array().is_some_and(|a| !a.is_empty()) {
                                    findings.push(Finding::new(
                                        "SEARCHSPLOIT-EXPL-FOUND",
                                        Category::Vulnerability,
                                        Severity::High,
                                        &format!("Public exploits found for '{}'", query),
                                        serde_json::json!({ "exploits": results, "query": query })
                                    )
                                    .with_mitre_attack(vec!["T1588.006".to_string()])
                                    .with_tactical_path("Investigate identified exploits and patch the affected software."));
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(findings)
    }
}
