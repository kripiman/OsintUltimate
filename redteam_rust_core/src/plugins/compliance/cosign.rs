use crate::plugins::{ScannerPlugin, Capability};
use crate::models::{TargetHost, Finding, Severity, Category};
use crate::utils::tool_detection::detect_tool;
use crate::utils::config::Config;
use crate::models::constants::*;
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::{info, error, warn};
use std::process::Stdio;
use tokio::process::Command;

pub struct CosignScanner {
    binary_path: String,
}

impl Default for CosignScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl CosignScanner {
    pub fn new() -> Self {
        let path = detect_tool("cosign");
        Self {
            binary_path: path,
        }
    }
}

#[async_trait]
impl ScannerPlugin for CosignScanner {
    fn name(&self) -> &'static str {
        PLUGIN_COSIGN
    }

    fn metadata(&self) -> crate::plugins::PluginMetadata {
        crate::plugins::PluginMetadata {
            name: self.name().to_string(),
            description: "Signature and provenance verification for container images using Cosign.".to_string(),
            target_type: crate::plugins::TargetType::Container,
            risk_level: crate::plugins::RiskLevel::Medium,
            layer: crate::core::capability_layer::ScanLayer::Scanning,
            expected_duration: std::time::Duration::from_secs(SUPPLY_TIMEOUT_COSIGN_SECS),
            capabilities: vec![Capability::VulnerabilityScanning],
            cost: 3,
            category: "Compliance".to_string(),
            mitre_attacks: vec!["T1553".to_string()],
            exploit_difficulty: crate::plugins::RiskLevel::Medium,
            blackarch_category: None,
            is_destructive: false,
            poc_mode: false, ..Default::default() }
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::VulnerabilityScanning]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability("cosign").await)
    }

    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        info!("CosignScanner: verifying signature for image: {}", target.host);

        let config = Config::from_env();
        let mut findings = Vec::new();

        let mut cmd = Command::new(&self.binary_path);
        cmd.arg("verify");

        // Verification logic: Key-based or Keyless (OIDC)
        if let Some(key_path) = config.cosign_public_key {
            cmd.arg("--key").arg(key_path);
        } else if let Some(oidc_issuer) = config.cosign_oidc_issuer {
            // Keyless verification (Sigstore default)
            cmd.arg("--certificate-oidc-issuer").arg(oidc_issuer);
            if let Ok(identity) = std::env::var("COSIGN_CERTIFICATE_IDENTITY") {
                cmd.arg("--certificate-identity").arg(identity);
            }
        } else {
            // Default to keyless if no key provided
            cmd.arg("--allow-http-registry"); 
            cmd.arg("--certificate-identity-regexp").arg(".*");
            cmd.arg("--certificate-oidc-issuer-regexp").arg(".*");
        }

        cmd.arg(&target.host)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let timeout_duration = std::time::Duration::from_secs(SUPPLY_TIMEOUT_COSIGN_SECS);
        let output = match tokio::time::timeout(timeout_duration, cmd.spawn()?.wait_with_output()).await {
            Ok(res) => res.context("Failed to wait for cosign")?,
            Err(_) => {
                warn!("CosignScanner timed out verifying {}", target.host);
                return Ok(findings);
            }
        };

        if output.status.success() {
            findings.push(Finding::new(
                "IMAGE-SIGNATURE-VERIFIED",
                Category::Compliance,
                Severity::Info,
                &format!("Container image signature verified: {}", target.host),
                serde_json::json!({
                    "image": target.host,
                    "status": "verified",
                    "tool": "cosign"
                })
            ));
        } else {
            let err = String::from_utf8_lossy(&output.stderr);
            if err.contains("no matching signatures") || err.contains("could not find signatures") {
                findings.push(Finding::new(
                    FINDING_UNSIGNED_IMAGE,
                    Category::Compliance,
                    Severity::High,
                    &format!("UNSIGNED IMAGE DETECTED: {}", target.host),
                    serde_json::json!({
                        "image": target.host,
                        "status": "unsigned",
                        "error": err.trim()
                    })
                ).with_mitre_attack(vec!["T1553".to_string()]));
            } else {
                error!("CosignScanner error: {}", err);
            }
        }

        Ok(findings)
    }
}
