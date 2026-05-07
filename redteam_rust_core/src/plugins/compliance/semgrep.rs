use crate::plugins::{ScannerPlugin, Capability, PluginMetadata, RiskLevel, TargetType};
use crate::models::{TargetHost, Finding, Severity, Category};
use crate::utils::tool_detection::detect_tool;
use crate::core::capability_layer::ScanLayer;
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::{info, warn, debug};
use std::process::Stdio;
use tokio::process::Command;

pub struct SemgrepScanner {
    binary_path: String,
}

impl Default for SemgrepScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl SemgrepScanner {
    pub fn new() -> Self {
        let path = detect_tool("semgrep");
        Self {
            binary_path: path,
        }
    }
}

#[async_trait]
impl ScannerPlugin for SemgrepScanner {
    fn name(&self) -> &'static str {
        "semgrep"
    }

    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: self.name().to_string(),
            description: "Semgrep: Static Analysis Security Testing (SAST) for finding vulnerabilities in source code.".to_string(),
            target_type: TargetType::Host, // Can scan local paths or repositories
            risk_level: RiskLevel::Safe,
            layer: ScanLayer::Scanning,
            category: "Compliance".to_string(),
            expected_duration: std::time::Duration::from_secs(300),
            capabilities: vec![Capability::SecurityAuditing],
            cost: 5,
            mitre_attacks: vec!["T1592".to_string()],
            exploit_difficulty: RiskLevel::Medium,
            ..Default::default()
        }
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::SecurityAuditing]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability("semgrep").await)
    }

    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        // Reactive Trigger check: Is there a local path to scan?
        let scan_path = if std::path::Path::new(&target.host).is_dir() {
            Some(target.host.clone())
        } else if let Some(p) = target.tactical_context.get("source_path").and_then(|v| v.as_str()) {
            Some(p.to_string())
        } else if target.findings.iter().any(|f| f.title.to_lowercase().contains("leaked source code") || f.title.to_lowercase().contains("github secret")) {
            // If leaked code is found but no path is provided, we can't scan yet.
            // In a real pipeline, the previous plugin would have cloned the repo.
            None
        } else {
            None
        };

        let path = match scan_path {
            Some(p) => p,
            None => {
                debug!("SemgrepScanner: No local source path found for {}. Skipping.", target.host);
                return Ok(Vec::new());
            }
        };

        info!("SemgrepScanner: auditing source code at {}", path);

        let output = Command::new(&self.binary_path)
            .arg("scan")
            .arg("--config").arg("auto")
            .arg("--json")
            .arg(&path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .context("Failed to execute semgrep")?;

        let mut findings = Vec::new();
        if output.status.success() {
            let content = String::from_utf8_lossy(&output.stdout);
            if let Ok(json_data) = serde_json::from_str::<serde_json::Value>(&content) {
                if let Some(results) = json_data.get("results").and_then(|r| r.as_array()) {
                    for res in results {
                        let check_id = res.get("check_id").and_then(|v| v.as_str()).unwrap_or("unknown_rule");
                        let message = res.get("extra").and_then(|e| e.get("message")).and_then(|v| v.as_str()).unwrap_or("No description");
                        let severity_str = res.get("extra").and_then(|e| e.get("severity")).and_then(|v| v.as_str()).unwrap_or("info");
                        let file = res.get("path").and_then(|v| v.as_str()).unwrap_or("unknown");
                        let line = res.get("start").and_then(|s| s.get("line")).and_then(|v| v.as_u64()).unwrap_or(0);

                        let severity = match severity_str.to_lowercase().as_str() {
                            "error" => Severity::High,
                            "warning" => Severity::Medium,
                            _ => Severity::Low,
                        };

                        findings.push(Finding::new(
                            "SAST_VULNERABILITY",
                            Category::Vulnerability,
                            severity,
                            &format!("Semgrep: {} in {}:{}", check_id, file, line),
                            serde_json::json!({
                                "rule_id": check_id,
                                "file": file,
                                "line": line,
                                "message": message,
                                "snippet": res.get("extra").and_then(|e| e.get("lines")),
                            })
                        ).with_tactical_path("Review the identified code pattern and apply suggested remediation. Check for hardcoded secrets or insecure API usage."));
                    }
                }
            }
        } else {
            let err = String::from_utf8_lossy(&output.stderr);
            warn!("SemgrepScanner error: {}", err);
        }

        Ok(findings)
    }
}
