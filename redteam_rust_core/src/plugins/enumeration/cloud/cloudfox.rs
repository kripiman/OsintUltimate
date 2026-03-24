use crate::plugins::{ScannerPlugin, Capability};
use crate::models::{TargetHost, Finding, Severity, Category};
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::{info, warn};
use std::process::Stdio;
use tokio::process::Command;

pub struct CloudFoxScanner {
    binary_path: String,
}

impl CloudFoxScanner {
    pub fn new() -> Self {
        let path = which::which("cloudfox")
            .unwrap_or_else(|_| "cloudfox".into());
            
        Self {
            binary_path: path.to_string_lossy().to_string(),
        }
    }
}

#[async_trait]
impl ScannerPlugin for CloudFoxScanner {
    fn name(&self) -> &'static str {
        crate::models::PLUGIN_CLOUDFOX
    }

    
        fn metadata(&self) -> crate::plugins::PluginMetadata {
        crate::plugins::PluginMetadata {
            name: self.name(),
            description: "Automated security analysis using this plugin.",
            target_type: crate::plugins::TargetType::Cloud,
            risk_level: crate::plugins::RiskLevel::Medium,
            layer: crate::core::capability_layer::ScanLayer::Passive,
            expected_duration: std::time::Duration::from_secs(300),
            capabilities: self.capabilities(),
            cost: 5,
            category: "Enumeration",
            mitre_attacks: vec![],
            remediation_difficulty: crate::plugins::RiskLevel::Medium,
        }
    }
    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::VulnerabilityScanning]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        Ok(which::which("cloudfox").is_ok())
    }


    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        info!("CloudFoxScanner: enumerating cloud assets for {}", target.host);

        // cloudfox aws -u <target> -v
        let child = Command::new(&self.binary_path)
            .arg("aws")
            .arg("all")
            .arg("-t")
            .arg(&target.host)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .context("Failed to spawn cloudfox")?;

        let output = child.wait_with_output().await.context("Failed to wait for cloudfox")?;

        let mut findings = Vec::new();
        let content = String::from_utf8_lossy(&output.stdout);
        
        if !content.is_empty() {
            findings.push(Finding::new(
                "CLOUDFOX-ASSET-ENUM",
                Category::ExposedAsset,
                Severity::Medium,
                &format!("Cloud assets enumerated for {} via CloudFox.", target.host),
                serde_json::json!({ "output": content.trim() })
            ));
        }

        Ok(findings)
    }
}
