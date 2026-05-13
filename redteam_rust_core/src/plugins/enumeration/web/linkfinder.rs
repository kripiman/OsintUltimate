// src/plugins/enumeration/web/linkfinder.rs
// 🔍 LinkFinder: Endpoints discovery in JS files
// ⚡ Offensive reconnaissance for front-end analysis

use async_trait::async_trait;
use crate::models::{TargetHost, Finding, Category, Severity};
use crate::plugins::{ScannerPlugin, PluginMetadata, Capability, RiskLevel};
use crate::core::capability_layer::ScanLayer;
use crate::models::constants::{PLUGIN_LINKFINDER, FINDING_JS_ENDPOINT};
use crate::utils::executor::{StealthExecutor, ExecutorMode};
use crate::plugins::GlobalConfig;
use anyhow::{Result, Context};
use std::sync::Arc;

pub struct LinkFinderScanner<M: ExecutorMode> {
    executor: Arc<StealthExecutor<M>>,
}

impl<M: ExecutorMode> LinkFinderScanner<M> {
    pub fn new(config: &GlobalConfig<M>) -> Self {
        Self {
            executor: config.executor.clone(),
        }
    }
}

#[async_trait]
impl<M: ExecutorMode> ScannerPlugin for LinkFinderScanner<M> {
    fn name(&self) -> &'static str {
        PLUGIN_LINKFINDER
    }

    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: self.name().to_string(),
            description: "Extracts endpoints and parameters from Javascript files using regex analysis.".to_string(),
            target_type: crate::models::TargetType::Web,
            risk_level: RiskLevel::Low,
            layer: ScanLayer::Scanning,
            category: "Web/Enumeration".to_string(),
            expected_duration: std::time::Duration::from_secs(300),
            capabilities: vec![Capability::VulnerabilityScanning],
            cost: 2,
            mitre_attacks: vec!["T1592".to_string()],
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
            .arg("linkfinder")
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
                "linkfinder",
                vec!["-i".to_string(), js_url.clone(), "-o".to_string(), "cli".to_string()],
            ).await.context("Failed to execute linkfinder")?;

            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with("LinkFinder") || line.contains("---") {
                        continue;
                    }
                    
                    findings.push(Finding::new(
                        FINDING_JS_ENDPOINT,
                        Category::Recon,
                        Severity::Info,
                        &format!("Discovered endpoint in {}: {}", js_url, line),
                        serde_json::json!({
                            "source": js_url,
                            "endpoint": line,
                            "tool": "linkfinder"
                        })
                    ).with_blackarch_category("recon"));
                }
            }
        }

        Ok(findings)
    }
}
