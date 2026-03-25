use crate::plugins::{ScannerPlugin, Capability, PluginMetadata, RiskLevel};
use crate::models::{TargetHost, Finding, Severity, Category, TargetType};
use crate::utils::tool_detection::detect_tool;
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::{info, warn};
use std::process::Stdio;
use tokio::process::Command;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct OSVResult {
    results: Vec<OSVPackageResult>,
}

#[derive(Debug, Deserialize)]
struct OSVPackageResult {
    packages: Vec<OSVPackage>,
}

#[derive(Debug, Deserialize)]
struct OSVPackage {
    package: PackageInfo,
    vulnerabilities: Vec<OSVVulnerability>,
}

#[derive(Debug, Deserialize)]
struct PackageInfo {
    name: String,
    version: String,
    ecosystem: String,
}

#[derive(Debug, Deserialize)]
struct OSVVulnerability {
    id: String,
    summary: Option<String>,
    details: Option<String>,
    modified: String,
    published: Option<String>,
    database_specific: Option<serde_json::Value>,
}

pub struct OSVScanner {
    binary_path: String,
}

impl OSVScanner {
    pub fn new() -> Self {
        let path = detect_tool("osv-scanner");
        Self {
            binary_path: path,
        }
    }
}

#[async_trait]
impl ScannerPlugin for OSVScanner {
    fn name(&self) -> &'static str {
        crate::models::PLUGIN_OSV_SCANNER
    }

    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: self.name().to_string(),
            description: "Google's OSV-Scanner for identifying vulnerabilities in project dependencies (SCA).".to_string(),
            target_type: TargetType::Host, // Can be used on a host where code resides
            risk_level: RiskLevel::Safe,
            layer: crate::core::capability_layer::ScanLayer::Passive,
            expected_duration: std::time::Duration::from_secs(60),
            capabilities: self.capabilities(),
            cost: 2,
            category: "Compliance".to_string(),
            mitre_attacks: vec![],
            remediation_difficulty: crate::plugins::RiskLevel::Medium,
            blackarch_category: None,
            is_destructive: false,
            poc_mode: false,
        }
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::SCA, Capability::SecurityAuditing]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability("osv-scanner").await)
    }

    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        info!("OSVScanner: launching scan against {}", target.host);

        // OSV-Scanner usually runs against a directory. For a TargetHost, we might assume it's a path if target_type is Host.
        // If it's a remote host, this plugin might need a different approach (e.g., via SSH), 
        // but for now, let's assume local path scanning for professional supply chain auditing.
        
        let mut findings = Vec::new();
        
        // If the host looks like a path, use it. Otherwise, skip gracefully if not applicable.
        if !target.host.contains('/') && !target.host.contains('.') && target.host != "localhost" {
             return Ok(findings);
        }

        let mut cmd = Command::new(&self.binary_path);
        cmd.arg("-r") // recursive
           .arg("--json")
           .arg(&target.host)
           .stdin(Stdio::null())
           .stdout(Stdio::piped())
           .stderr(Stdio::null());

        let output = cmd.output().await.context("Failed to execute osv-scanner")?;

        if !output.status.success() && output.status.code() != Some(1) {
            warn!("osv-scanner returned error status: {:?}", output.status.code());
        }

        if let Ok(res) = serde_json::from_slice::<OSVResult>(&output.stdout) {
            for pkg_res in res.results {
                for pkg in pkg_res.packages {
                    for vuln in pkg.vulnerabilities {
                        let mut description = format!(
                            "Dependency Vulnerability in {}@{} ({}): {}",
                            pkg.package.name,
                            pkg.package.version,
                            pkg.package.ecosystem,
                            vuln.summary.as_deref().unwrap_or("No summary provided")
                        );
                        
                        if let Some(details) = &vuln.details {
                            description.push_str(&format!("\n\nDetails: {}", details));
                        }

                        findings.push(Finding::new(
                            crate::models::FINDING_SCA_VULN,
                            Category::SCA,
                            Severity::High, // Default to High for SCA findings
                            &description,
                            serde_json::json!({
                                "package": pkg.package.name,
                                "version": pkg.package.version,
                                "ecosystem": pkg.package.ecosystem,
                                "vuln_id": vuln.id,
                                "modified": vuln.modified,
                            })
                        ).with_references(vec![format!("https://osv.dev/vulnerability/{}", vuln.id)]));
                    }
                }
            }
        }

        Ok(findings)
    }
}
