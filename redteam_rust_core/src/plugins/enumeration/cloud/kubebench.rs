use crate::plugins::{ScannerPlugin, Capability, PluginMetadata, TargetType, RiskLevel};
use crate::models::{TargetHost, Finding, Severity, Category, PLUGIN_KUBE_BENCH};
use crate::utils::tool_detection::detect_tool;
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::{info, error};
use std::process::Stdio;
use tokio::process::Command;
use std::time::Duration;

pub struct KubeBenchScanner {
    binary_path: String,
}

impl KubeBenchScanner {
    pub fn new() -> Self {
        let path = detect_tool("kube-bench");
        Self {
            binary_path: path.to_string_lossy().to_string(),
        }
    }
}

#[async_trait]
impl ScannerPlugin for KubeBenchScanner {
    fn name(&self) -> &'static str {
        PLUGIN_KUBE_BENCH
    }

    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: self.name(),
            description: "kube-bench is a tool that checks whether Kubernetes is deployed securely by running the checks documented in the CIS Kubernetes Benchmark.",
            target_type: TargetType::Container,
            risk_level: RiskLevel::Safe,
            layer: crate::core::capability_layer::ScanLayer::Passive,
            expected_duration: Duration::from_secs(120),
            capabilities: self.capabilities(),
            cost: 3,
            category: "Enumeration",
            mitre_attacks: vec![],
            remediation_difficulty: crate::plugins::RiskLevel::Medium,
        }
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::InfrastructureAudit, Capability::ConfigAudit]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability("kube-bench").await)
    }

    async fn scan(&self, _target: &TargetHost) -> Result<Vec<Finding>> {
        info!("KubeBenchScanner: starting Kubernetes CIS benchmark");
        
        let mut findings = Vec::new();
        let output = Command::new(&self.binary_path)
            .arg("run")
            .arg("--json")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output()
            .await
            .context("Failed to execute kube-bench")?;

        let content = String::from_utf8_lossy(&output.stdout);
        // Kube-bench output contains multiple sections.
        if let Ok(results) = serde_json::from_str::<serde_json::Value>(&content) {
            if let Some(Totals) = results["Totals"].as_object() {
                if let Some(fail_count) = Totals["total_fail"].as_u64() {
                    if fail_count > 0 {
                        findings.push(Finding::new(
                            "KUBE-BENCH-FAILURES",
                            Category::Misconfiguration,
                            Severity::High,
                            &format!("Kubernetes CIS Benchmark found {} failures", fail_count),
                            serde_json::json!({
                                "total_fail": fail_count,
                                "total_warn": results["Totals"]["total_warn"],
                                "total_pass": results["Totals"]["total_pass"]
                            })
                        ));
                        
                        // Add specific failures if needed, but summary is usually enough for a quick overview.
                    }
                }
            }
        }

        Ok(findings)
    }
}
