// src/plugins/enumeration/web/secretfinder.rs
// 🔑 SecretFinder: Sensitive data discovery in JS files
// ⚡ Offensive reconnaissance for finding leaked credentials

use async_trait::async_trait;
use crate::models::{TargetHost, Finding, Category, Severity};
use crate::plugins::{ScannerPlugin, PluginMetadata, Capability, RiskLevel};
use crate::core::capability_layer::ScanLayer;
use crate::models::constants::{PLUGIN_SECRETFINDER, FINDING_JS_SECRET};
use crate::utils::executor::{StealthExecutor, ExecutorMode};
use crate::plugins::GlobalConfig;
use anyhow::{Result, Context};
use std::sync::Arc;

pub struct SecretFinderScanner<M: ExecutorMode> {
    executor: Arc<StealthExecutor<M>>,
}

impl<M: ExecutorMode> SecretFinderScanner<M> {
    pub fn new(config: &GlobalConfig<M>) -> Self {
        Self {
            executor: config.executor.clone(),
        }
    }
}

#[async_trait]
impl<M: ExecutorMode> ScannerPlugin for SecretFinderScanner<M> {
    fn name(&self) -> &'static str {
        PLUGIN_SECRETFINDER
    }

    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: self.name().to_string(),
            description: "Scans Javascript files for sensitive data like API keys, tokens, and credentials.".to_string(),
            target_type: crate::models::TargetType::Web,
            risk_level: RiskLevel::Medium,
            layer: ScanLayer::Scanning,
            category: "Web/Enumeration".to_string(),
            expected_duration: std::time::Duration::from_secs(400),
            capabilities: vec![Capability::VulnerabilityScanning],
            cost: 3,
            mitre_attacks: vec!["T1552".to_string()],
            exploit_difficulty: RiskLevel::Low,
            blackarch_category: Some("recon".to_string()),
            is_destructive: false,
            poc_mode: false, ..Default::default() }
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::VulnerabilityScanning]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        Ok(std::process::Command::new("which")
            .arg("SecretFinder")
            .status()
            .map(|s| s.success())
            .unwrap_or(false))
    }

    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        let js_files = if target.host.ends_with(".js") {
            vec![target.host.clone()]
        } else if let Some(discovered) = target.extra_data.get("discovered_urls") {
            if let Ok(urls) = serde_json::from_value::<Vec<String>>(discovered.clone()) {
                urls.into_iter().filter(|u| u.ends_with(".js")).collect()
            } else {
                vec![]
            }
        } else {
            vec![]
        };

        for js_url in js_files {
            let output = self.executor.execute_and_wait(
                "SecretFinder",
                vec!["-i".to_string(), js_url.clone(), "-o".to_string(), "cli".to_string()],
            ).await.context("Failed to execute SecretFinder")?;

            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    let line = line.trim();
                    if line.is_empty() || !line.contains("->") {
                        continue;
                    }
                    
                    findings.push(Finding::new(
                        FINDING_JS_SECRET,
                        Category::Vulnerability,
                        Severity::Medium,
                        &format!("Found secret in {}: {}", js_url, line),
                        serde_json::json!({
                            "source": js_url,
                            "match": line,
                            "secret": line.to_string(),
                            "tool": "SecretFinder"
                        })
                    ).with_blackarch_category("recon"));
                }
            }
        }

        Ok(findings)
    }
}
