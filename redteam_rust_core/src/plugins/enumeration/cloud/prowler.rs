use crate::plugins::{ScannerPlugin, Capability, PluginMetadata, TargetType, RiskLevel};
use crate::models::{TargetHost, Finding, Severity, Category, PLUGIN_PROWLER};
use crate::utils::tool_detection::detect_tool;
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::info;
use std::process::Stdio;
use tokio::process::Command;
use std::time::Duration;

pub struct ProwlerScanner {
    binary_path: String,
}

impl Default for ProwlerScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl ProwlerScanner {
    pub fn new() -> Self {
        let path = detect_tool("prowler");
        Self {
            binary_path: path,
        }
    }
}

#[async_trait]
impl ScannerPlugin for ProwlerScanner {
    fn name(&self) -> &'static str {
        PLUGIN_PROWLER
    }

    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: self.name().to_string(),
            description: "Prowler is an Open Source security tool to perform AWS security best practices assessments, audits, incident response, continuous monitoring, hardening and forensics readiness.".to_string(),
            target_type: TargetType::Cloud,
            risk_level: RiskLevel::Safe,
            layer: crate::core::capability_layer::ScanLayer::Passive,
            expected_duration: Duration::from_secs(600),
            capabilities: self.capabilities(),
            cost: 7,
            category: "Enumeration".to_string(),
            mitre_attacks: vec![],
            exploit_difficulty: crate::plugins::RiskLevel::Medium,
            blackarch_category: None,
            is_destructive: false,
            poc_mode: false, ..Default::default() }
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::CloudAudit, Capability::ConfigAudit, Capability::IAMAssessment]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability("prowler").await)
    }

    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        info!("ProwlerScanner: starting AWS audit for {}", target.host);
        
        // Prowler usually requires AWS credentials in the environment.
        // For this plugin, we assume they are present or managed via profiles.
        
        let mut findings = Vec::new();
        let output = Command::new(&self.binary_path)
            .arg("aws")
            .arg("-M").arg("json")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output()
            .await
            .context("Failed to execute Prowler")?;

        let content = String::from_utf8_lossy(&output.stdout);
        // Prowler output is a large JSON. We should parse it carefully.
        // For now, we'll look for FAIL results.
        
        if let Ok(results) = serde_json::from_str::<serde_json::Value>(&content) {
            if let Some(results_array) = results.as_array() {
                for res in results_array {
                    if res["Status"] == "FAIL" {
                        let severity = match res["Severity"].as_str() {
                            Some("critical") => Severity::Critical,
                            Some("high") => Severity::High,
                            _ => Severity::Medium,
                        };
                        
                        findings.push(Finding::new(
                            &format!("PROWLER-{}", res["CheckID"].as_str().unwrap_or("UNKNOWN")),
                            Category::Misconfiguration,
                            severity,
                            res["CheckTitle"].as_str().unwrap_or("AWS Check Failed"),
                            serde_json::json!({
                                "ResourceID": res["ResourceID"],
                                "Region": res["Region"],
                                "StatusExtended": res["StatusExtended"]
                            })
                        ));
                    }
                }
            }
        }

        Ok(findings)
    }
}
