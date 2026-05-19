use crate::plugins::{ScannerPlugin, Capability};
use crate::models::{TargetHost, Finding, Severity, Category, PLUGIN_GITLEAKS, FINDING_GITLEAKS_SECRET};
use crate::utils::tool_detection::detect_tool;
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::{info, warn};
use std::process::Stdio;
use tokio::process::Command;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
struct GitleaksFinding {
    #[serde(rename = "Description")]
    description: String,
    #[serde(rename = "File")]
    file: String,
    #[serde(rename = "RuleID")]
    rule_id: String,
    #[serde(rename = "Secret")]
    secret: String,
    #[serde(rename = "Line")]
    line: i32,
}

pub struct GitleaksScanner {
    binary_path: String,
}

impl Default for GitleaksScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl GitleaksScanner {
    pub fn new() -> Self {
        let path = detect_tool("gitleaks");
        Self {
            binary_path: path,
        }
    }
}

#[async_trait]
impl ScannerPlugin for GitleaksScanner {
    fn name(&self) -> &'static str {
        PLUGIN_GITLEAKS
    }

    
    fn metadata(&self) -> crate::plugins::PluginMetadata {
        crate::plugins::PluginMetadata {
            name: self.name().to_string(),
            description: "Automated secret scanning using Gitleaks.".to_string(),
            category: "Reconnaissance".to_string(),
            capabilities: self.capabilities(),
            ..crate::plugins::PluginMetadata::default()
        }
    }
    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::SecretDiscovery]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability("gitleaks").await)
    }


    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        info!("GitleaksScanner: searching for secrets on {}", target.host);

        let temp_file = tempfile::NamedTempFile::new().context("Failed to create temp file for Gitleaks")?;
        let temp_path = temp_file.path().to_string_lossy().to_string();

        let mut cmd = Command::new(&self.binary_path);
        cmd.arg("detect")
           .arg("--source").arg(&target.host)
           .arg("--report-format").arg("json")
           .arg("--report-path").arg(&temp_path)
           .stdin(Stdio::null())
           .stdout(Stdio::null())
           .stderr(Stdio::null());

        let status = cmd.spawn()?.wait().await.context("Failed to wait for gitleaks")?;

        let mut findings = Vec::new();

        // Gitleaks returns 1 if leaks are found, which is fine.
        if status.code() == Some(1) || status.success() {
            if let Ok(content) = tokio::fs::read_to_string(&temp_path).await {
                if let Ok(leaks) = serde_json::from_str::<Vec<GitleaksFinding>>(&content) {
                   for leak_obj in leaks {
                       findings.push(Finding::new(
                           FINDING_GITLEAKS_SECRET,
                           Category::CredentialLeak,
                           Severity::Critical,
                           &format!("Gitleaks: {} found in {}", leak_obj.description, leak_obj.file),
                           serde_json::json!({
                               "rule_id": leak_obj.rule_id,
                               "file": leak_obj.file,
                               "line": leak_obj.line,
                               "secret": leak_obj.secret.clone(),
                               "secret_preview": format!("{}...", &leak_obj.secret[..std::cmp::min(leak_obj.secret.len(), 10)])
                           })
                       ).with_tactical_path("Revoke the exposed secret and remove it from the source history."));
                   }
                }
            }
        } else {
            warn!("Gitleaks failed on {} with status {:?}", target.host, status.code());
        }

        Ok(findings)
    }
}
