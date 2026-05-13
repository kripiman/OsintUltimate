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

pub struct SchemathesisScanner {
    binary_path: String,
}

impl SchemathesisScanner {
    pub fn new() -> Self {
        Self { binary_path: detect_tool("schemathesis") }
    }
}

impl Default for SchemathesisScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ScannerPlugin for SchemathesisScanner {
    fn name(&self) -> &'static str { "schemathesis" }
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: self.name().to_string(),
            description: "Property-based testing for API schemas (OpenAPI, GraphQL)".to_string(),
            target_type: TargetType::Web,
            risk_level: RiskLevel::Safe,
            layer: ScanLayer::Scanning,
            category: "API Security".to_string(),
            expected_duration: std::time::Duration::from_secs(120),
            capabilities: vec![Capability::VulnerabilityScanning],
            cost: 3,
            mitre_attacks: vec!["T1595.002".to_string()],
            exploit_difficulty: RiskLevel::Medium,
            blackarch_category: Some("webapp".to_string()),
            is_destructive: false,
            poc_mode: true, ..Default::default() }
    }

    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability("schemathesis").await)
    }

    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        let target_url = target.extra_data.get("api_schema_url")
            .and_then(|v| v.as_str())
            .unwrap_or(&format!("https://{}/graphql", target.host))
            .to_string();

        info!("SchemathesisScanner: scanning API schema at {}", target_url);

        let child = Command::new(&self.binary_path)
            .arg("run")
            .arg(&target_url)
            .arg("--checks")
            .arg("all")
            .arg("--max-failures")
            .arg("1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn();

        match child {
            Ok(c) => {
                let output = c.wait_with_output().await.context("Failed to wait for schemathesis")?;
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);
                let content = format!("{}\n{}", stdout, stderr);
                let content_lower = content.to_lowercase();
                
                info!("SchemathesisScanner: tool finished with exit code {}. Content length: {}", output.status.code().unwrap_or(-1), content.len());

                if !output.status.success() {
                    if content_lower.contains("vulnerability found") || content_lower.contains("falsifying example found") {
                        return Ok(vec![Finding::new(
                            FINDING_API_SCHEMA_VULN,
                            Category::Vulnerability,
                            Severity::High,
                            &format!("Schemathesis found vulnerabilities in {}", target_url),
                            serde_json::json!({
                                "url": target_url,
                                "output": content.chars().take(2000).collect::<String>(),
                                "tool": "schemathesis"
                            })
                        )]);
                    } else if content_lower.contains("too many requests") || content_lower.contains("429") {
                         return Ok(vec![Finding::new(
                            FINDING_API_SCAN_INHIBITED,
                            Category::Vulnerability,
                            Severity::Info,
                            &format!("API Schema scan inhibited by rate limit for {}", target_url),
                            serde_json::json!({
                                "url": target_url,
                                "status": "Rate Limited (429)",
                                "tool": "schemathesis"
                            })
                        )]);
                    }
                } else if output.status.success() {
                    return Ok(vec![Finding::new(
                        "API-SCHEMA-CLEAN",
                        Category::Vulnerability,
                        Severity::Info,
                        &format!("API Schema verified clean for {}", target_url),
                        serde_json::json!({
                            "url": target_url,
                            "status": "No issues detected",
                            "tool": "schemathesis"
                        })
                    )]);
                }

                // Fallthrough: Tool exited with non-zero but we didn't match vulns or 429
                return Ok(vec![Finding::new(
                    FINDING_API_SCAN_FAILED,
                    Category::Vulnerability,
                    Severity::Info,
                    &format!("Schemathesis terminated without parseable output for {}", target_url),
                    serde_json::json!({
                        "url": target_url,
                        "exit_code": output.status.code(),
                        "output_tail": content.chars().take(500).collect::<String>(),
                        "tool": "schemathesis"
                    })
                )]);
            }
            Err(e) => {
                error!("SchemathesisScanner failed to spawn: {}", e);
            }
        }

        Ok(Vec::new())
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::VulnerabilityScanning]
    }
}
