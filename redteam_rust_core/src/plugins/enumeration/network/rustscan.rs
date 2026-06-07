use crate::plugins::{ScannerPlugin, Capability};
use crate::models::{TargetHost, Finding, Severity, Category};
use crate::utils::tool_detection::detect_tool;
use crate::utils::executor::{StealthExecutor, ExecutorMode};
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::info;
use std::sync::Arc;

pub struct RustScanScanner<M: ExecutorMode> {
    binary_path: String,
    executor: Arc<StealthExecutor<M>>,
}

impl<M: ExecutorMode> Default for RustScanScanner<M> {
    fn default() -> Self {
        Self::new(Arc::new(StealthExecutor::new(
            Arc::new(crate::core::policy::ReloadablePolicy::new(None)),
            None,
            false,
        )))
    }
}

impl<M: ExecutorMode> RustScanScanner<M> {
    pub fn new(executor: Arc<StealthExecutor<M>>) -> Self {
        let path = detect_tool("rustscan");
        Self {
            binary_path: path,
            executor,
        }
    }
}

#[async_trait]
impl<M: ExecutorMode> ScannerPlugin for RustScanScanner<M> {
    fn name(&self) -> &'static str {
        crate::models::PLUGIN_RUSTSCAN
    }

    
        fn metadata(&self) -> crate::plugins::PluginMetadata {
        crate::plugins::PluginMetadata {
            name: self.name().to_string(),
            description: "Automated security analysis using this plugin.".to_string(),
            target_type: crate::plugins::TargetType::Network,
            risk_level: crate::plugins::RiskLevel::Medium,
            layer: crate::core::capability_layer::ScanLayer::Discovery,
            expected_duration: std::time::Duration::from_secs(300),
            capabilities: self.capabilities(),
            cost: 5,
            category: "Enumeration".to_string(),
            mitre_attacks: vec!["T1046".to_string()],
            exploit_difficulty: crate::plugins::RiskLevel::Low,
            blackarch_category: Some("scanner".to_string()),
            is_destructive: false,
            poc_mode: true, ..Default::default() }
    }
    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::PortScanning]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability("rustscan").await)
    }


    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        let target_addr = target.pinned_addr()?;
        info!("RustScanScanner: scanning ports for {}", target_addr);

        let args = vec![
            "-a".to_string(), target_addr.to_string(),
            "--ulimit".to_string(), "5000".to_string(),
            "--quiet".to_string(),
            "--".to_string(),
            "-sV".to_string(),
        ];

        let output = self.executor.execute_and_wait(&self.binary_path, args).await
            .context("RustScan execution failed via StealthExecutor")?;

        let mut findings = Vec::new();
        let content = String::from_utf8_lossy(&output.stdout);
        
        // Basic parsing of rustscan/nmap output to find open ports
        for line in content.lines() {
            if line.contains("/tcp") && line.contains("open") {
                findings.push(Finding::new(
                    crate::models::FINDING_PORT_OPEN,
                    Category::NetworkPort,
                    Severity::Low,
                    &format!("RustScan detected an open port on {}: {}", target_addr, line.trim()),
                    serde_json::json!({ "output": line.trim() })
                ));
            }
        }

        Ok(findings)
    }
}
