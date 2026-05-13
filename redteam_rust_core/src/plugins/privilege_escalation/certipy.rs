use crate::plugins::{ScannerPlugin, Capability};
use crate::models::{TargetHost, Finding, Severity, Category};
use crate::utils::tool_detection::detect_tool;
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::info;
use std::process::Stdio;
use tokio::process::Command;
pub struct CertipyScanner {
    binary_path: String,
}
impl Default for CertipyScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl CertipyScanner {
    pub fn new() -> Self {
        let path = detect_tool("certipy");
        Self {
            binary_path: path,
        }
    }
}
#[async_trait]
impl ScannerPlugin for CertipyScanner {
    fn name(&self) -> &'static str {
        crate::models::PLUGIN_CERTIPY
    }
        fn metadata(&self) -> crate::plugins::PluginMetadata {
        crate::plugins::PluginMetadata {
            name: self.name().to_string(),
            description: "Automated security analysis using this plugin.".to_string(),
            target_type: crate::plugins::TargetType::Host,
            risk_level: crate::plugins::RiskLevel::Medium,
            layer: crate::core::capability_layer::ScanLayer::PostExploitation,
            expected_duration: std::time::Duration::from_secs(300),
            capabilities: self.capabilities(),
            cost: 5,
            category: "Privilege Escalation".to_string(),
            mitre_attacks: vec![],
            exploit_difficulty: crate::plugins::RiskLevel::Medium,
            blackarch_category: None,
            is_destructive: false,
            poc_mode: false, ..Default::default() }
    }
    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::VulnerabilityScanning]
    }
    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability("certipy").await)
    }
    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        info!("CertipyScanner: auditing AD CS on {}", target.host);
        // Certipy 'find' for vulnerable certificates
        let child = Command::new(&self.binary_path)
            .arg("find")
            .arg("-vulnerable")
            .arg("-target")
            .arg(&target.host)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .context("Failed to spawn Certipy")?;
        let output = child.wait_with_output().await.context("Failed to wait for Certipy")?;
        let mut findings = Vec::new();
        let content = String::from_utf8_lossy(&output.stdout);
        if content.contains("ESC1") || content.contains("ESC8") || content.contains("Vulnerable") {
            findings.push(Finding::new(
                "AD-CS-VULNERABLE",
                Category::Vulnerability,
                Severity::High,
                &format!("Active Directory Certificate Services (AD CS) vulnerability found on {}.", target.host),
                serde_json::json!({ "output": content.trim() })
            ).with_tactical_path("Fix permissions on Certificate Templates or disable NTLM authentication on CA Web Enrollment."));
        }
        Ok(findings)
    }
}
