use crate::plugins::{ScannerPlugin, Capability};
use crate::models::{TargetHost, Finding, Severity, Category};
use crate::utils::tool_detection::detect_tool;
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::{info, error, warn};
use std::process::Stdio;
use tokio::process::Command;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct WhatWebResult {
    target: String,
    plugins: serde_json::Value,
}

pub struct WhatWebScanner {
    binary_path: String,
}

impl WhatWebScanner {
    pub fn new() -> Self {
        let path = detect_tool("whatweb");
        Self {
            binary_path: path,
        }
    }
}

#[async_trait]
impl ScannerPlugin for WhatWebScanner {
    fn name(&self) -> &'static str {
        crate::models::PLUGIN_WHATWEB
    }

        fn metadata(&self) -> crate::plugins::PluginMetadata {
        crate::plugins::PluginMetadata {
            name: self.name().to_string(),
            description: "Technology stack fingerprinter using WhatWeb.".to_string(),
            target_type: crate::plugins::TargetType::Web,
            risk_level: crate::plugins::RiskLevel::Medium,
            layer: crate::core::capability_layer::ScanLayer::Discovery,
            expected_duration: std::time::Duration::from_secs(300),
            capabilities: self.capabilities(),
            cost: 5,
            category: "Enumeration".to_string(),
            mitre_attacks: vec![],
            remediation_difficulty: crate::plugins::RiskLevel::Medium,
            blackarch_category: None,
            is_destructive: false,
            poc_mode: false,
        }
    }
    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::VulnerabilityScanning]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability("whatweb").await)
    }


    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        let target_addr = target.pinned_addr()?;
        info!("WhatWebScanner: launching scan against {} (via {})", target.host, target_addr);

        let url = if target_addr.starts_with("http") {
            target_addr.to_string()
        } else {
            format!("http://{}", target_addr)
        };

        // We use a temporary file because some versions of WhatWeb don't support --log-json=- 
        let temp_file = tempfile::NamedTempFile::new().context("Failed to create temp file for WhatWeb")?;
        let temp_path = temp_file.path().to_string_lossy().to_string();
        
        let mut child = Command::new(&self.binary_path)
            .arg("--color=never")
            .arg(format!("--log-json={}", temp_path))
            .arg(&url)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to spawn whatweb")?;

        let status = child.wait().await.context("Failed to wait for WhatWeb")?;

        if !status.success() {
            warn!("WhatWeb failed on {}", target.host);
            return Ok(Vec::new());
        }

        let content = tokio::fs::read_to_string(&temp_path).await.context("Failed to read WhatWeb output")?;

        let results: Vec<WhatWebResult> = serde_json::from_str(&content).unwrap_or_default();
        
        let mut findings = Vec::new();

        for res in results {
            findings.push(Finding::new(
                crate::models::FINDING_TECH_STACK,
                Category::TechnologyStack,
                Severity::Info,
                &format!("Technology stack discovered for {}", res.target),
                serde_json::json!({
                    "target": res.target,
                    "plugins": res.plugins,
                })
            ));
        }

        Ok(findings)
    }
}
