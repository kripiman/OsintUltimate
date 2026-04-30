use crate::plugins::{ScannerPlugin, Capability};
use crate::models::{TargetHost, Finding, Severity, Category};
use crate::utils::tool_detection::detect_tool;
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::{info, warn};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct WhatWebResult {
    target: String,
    plugins: serde_json::Value,
}

use std::sync::Arc;
use crate::utils::executor::{StealthExecutor, ExecutorMode};

pub struct WhatWebScanner<M: ExecutorMode> {
    binary_path: String,
    executor: Arc<StealthExecutor<M>>,
}

impl<M: ExecutorMode> WhatWebScanner<M> {
    pub fn new(executor: Arc<StealthExecutor<M>>) -> Self {
        let path = detect_tool("whatweb");
        Self {
            binary_path: path,
            executor,
        }
    }
}

#[async_trait]
impl<M: ExecutorMode> ScannerPlugin for WhatWebScanner<M> {
    fn name(&self) -> &'static str {
        crate::models::PLUGIN_WHATWEB
    }

        fn metadata(&self) -> crate::plugins::PluginMetadata {
        crate::plugins::PluginMetadata {
            name: self.name().to_string(),
            description: "Technology stack fingerprinter using WhatWeb with mandatory proxying.".to_string(),
            target_type: crate::plugins::TargetType::Web,
            risk_level: crate::plugins::RiskLevel::Medium,
            layer: crate::core::capability_layer::ScanLayer::Discovery,
            expected_duration: std::time::Duration::from_secs(300),
            capabilities: self.capabilities(),
            cost: 5,
            category: "Enumeration".to_string(),
            mitre_attacks: vec!["T1592".to_string()], // Gather Victim Host Information
            ..Default::default()
        }
    }
    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::VulnerabilityScanning]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability("whatweb").await)
    }


    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        let _target_addr = target.pinned_addr()?;
        info!("🔱 V14.1 SOVEREIGN: Launching WhatWeb scan against {} via StealthExecutor...", target.host);

        let url = if target.host.starts_with("http") {
            target.host.to_string()
        } else {
            format!("http://{}", target.host)
        };

        // We use a temporary file because some versions of WhatWeb don't support --log-json=- 
        let temp_file = tempfile::NamedTempFile::new().context("Failed to create temp file for WhatWeb")?;
        let temp_path = temp_file.path().to_string_lossy().to_string();
        
        let args = vec![
            "--color=never".to_string(),
            format!("--log-json={}", temp_path),
            url,
        ];

        let output = self.executor.execute_and_wait(&self.binary_path, args).await?;

        if !output.status.success() {
            warn!("⚠️ WhatWeb failed on {}: {}", target.host, String::from_utf8_lossy(&output.stderr));
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
