use crate::plugins::{ScannerPlugin, Capability, PluginMetadata, RiskLevel, TargetType};
use crate::models::{TargetHost, Finding, Severity, Category};
use crate::core::capability_layer::ScanLayer;
use crate::utils::tool_detection::detect_tool;
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::{info, error};
use tokio::process::Command;
use std::process::Stdio;
use crate::models::constants::*;

pub struct CrackqlScanner {
    binary_path: String,
}

impl CrackqlScanner {
    pub fn new() -> Self {
        Self { binary_path: detect_tool("crackql") }
    }
}

impl Default for CrackqlScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ScannerPlugin for CrackqlScanner {
    fn name(&self) -> &'static str { "crackql" }
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: self.name().to_string(),
            description: "GraphQL brute-force and fuzzing tool".to_string(),
            target_type: TargetType::Web,
            risk_level: RiskLevel::Medium,
            layer: ScanLayer::Scanning,
            category: "API Security".to_string(),
            expected_duration: std::time::Duration::from_secs(90),
            capabilities: vec![Capability::VulnerabilityScanning],
            cost: 2,
            mitre_attacks: vec!["T1110".to_string()],
            exploit_difficulty: RiskLevel::Medium,
            blackarch_category: Some("webapp".to_string()),
            is_destructive: false,
            poc_mode: true, ..Default::default() }
    }

    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability("crackql").await)
    }

    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        let target_url = target.extra_data.get("api_schema_url")
            .and_then(|v| v.as_str())
            .unwrap_or(&format!("https://{}/graphql", target.host))
            .to_string();

        info!("CrackqlScanner: launching brute-force audit for {}", target_url);

        let child = Command::new(&self.binary_path)
            .arg("-t")
            .arg(&target_url)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn();

        match child {
            Ok(c) => {
                let output = c.wait_with_output().await.context("Failed to wait for crackql")?;
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);
                let content = format!("{}\n{}", stdout, stderr);
                let content_lower = content.to_lowercase();
                
                info!("CrackqlScanner: tool finished with exit code {}. Content length: {}", output.status.code().unwrap_or(-1), content.len());

                if output.status.success() {
                    if content_lower.contains("found") || content_lower.contains("password") || content_lower.contains("success") {
                        return Ok(vec![Finding::new(
                            FINDING_CREDENTIALS_FOUND,
                            Category::Vulnerability,
                            Severity::High,
                            &format!("CrackQL discovered credentials/sensitive info at {}", target_url),
                            serde_json::json!({
                                "url": target_url,
                                "output": content.chars().take(1000).collect::<String>(),
                                "tool": "crackql"
                            })
                        )]);
                    }
                    return Ok(vec![Finding::new(
                        "GRAPHQL-BRUTE-SECURE",
                        Category::Vulnerability,
                        Severity::Info,
                        &format!("GraphQL brute-force/security audit finished with no findings for {}", target_url),
                        serde_json::json!({
                            "url": target_url,
                            "status": "Secure",
                            "tool": "crackql"
                        })
                    )]);
                } else if content_lower.contains("usage") || content_lower.contains("error") {
                     return Ok(vec![Finding::new(
                        "GRAPHQL-BRUTE-ABORTED",
                        Category::Vulnerability,
                        Severity::Info,
                        &format!("GraphQL brute-force scan aborted (missing config) for {}", target_url),
                        serde_json::json!({
                            "url": target_url,
                            "status": "Aborted",
                            "tool": "crackql",
                            "note": "CrackQL requires specific queries/inputs for brute-force."
                        })
                    )]);
                }

                // Fallthrough: Tool exited with non-zero but we didn't match success or usage
                return Ok(vec![Finding::new(
                    FINDING_GRAPHQL_BRUTE_FAILED,
                    Category::Vulnerability,
                    Severity::Info,
                    &format!("CrackQL terminated without parseable output for {}", target_url),
                    serde_json::json!({
                        "url": target_url,
                        "exit_code": output.status.code(),
                        "output_tail": content.chars().take(500).collect::<String>(),
                        "tool": "crackql"
                    })
                )]);
            }
            Err(e) => {
                error!("CrackqlScanner failed to spawn: {}", e);
            }
        }

        Ok(Vec::new())
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::VulnerabilityScanning]
    }
}
