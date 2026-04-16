use crate::plugins::{ScannerPlugin, Capability};
use crate::models::{TargetHost, Finding, Severity, Category};
use crate::utils::tool_detection::detect_tool;
use async_trait::async_trait;
use anyhow::Result;
use tracing::info;
use std::sync::Arc;
use crate::utils::executor::{StealthExecutor, ExecutorMode};

pub struct DnsxScanner<M: ExecutorMode> {
    binary_path: String,
    executor: Arc<StealthExecutor<M>>,
}

impl<M: ExecutorMode> DnsxScanner<M> {
    pub fn new(executor: Arc<StealthExecutor<M>>) -> Self {
        let path = detect_tool("dnsx");
        Self {
            binary_path: path,
            executor,
        }
    }
}
#[async_trait]
impl<M: ExecutorMode> ScannerPlugin for DnsxScanner<M> {
    fn name(&self) -> &'static str {
        "dnsx"
    }
        fn metadata(&self) -> crate::plugins::PluginMetadata {
        crate::plugins::PluginMetadata {
            name: self.name().to_string(),
            description: "Multi-protocol DNS resolution (A/AAAA/CNAME/NS/MX/TXT) via dnsx with mandatory proxying.".to_string(),
            target_type: crate::plugins::TargetType::Host,
            risk_level: crate::plugins::RiskLevel::Medium,
            layer: crate::core::capability_layer::ScanLayer::Discovery,
            expected_duration: std::time::Duration::from_secs(300),
            capabilities: self.capabilities(),
            cost: 5,
            category: "Reconnaissance".to_string(),
            mitre_attacks: vec!["T1016".to_string()], // System Network Configuration Discovery
            ..Default::default()
        }
    }
    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::VulnerabilityScanning]
    }
    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability("dnsx").await)
    }
    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        info!("🔱 V14.1 SOVEREIGN: Running DNS queries for {} via StealthExecutor...", target.host);
        
        // dnsx execution
        let args = vec![
            "-d".to_string(), target.host.clone(),
            "-a".to_string(),
            "-aaaa".to_string(),
            "-cname".to_string(),
            "-ns".to_string(),
            "-mx".to_string(),
            "-txt".to_string(),
            "-resp-only".to_string(),
        ];

        let output = self.executor.execute_and_wait(&self.binary_path, args).await?;
        
        let mut findings = Vec::new();
        let content = String::from_utf8_lossy(&output.stdout);
        for line in content.lines() {
            if line.is_empty() { continue; }
            findings.push(Finding::new(
                "DNSX-RECORD",
                Category::Recon,
                Severity::Info,
                &format!("Discovered DNS record: {}", line),
                serde_json::json!({ "record": line.trim() })
            ));
        }
        Ok(findings)
    }
}
