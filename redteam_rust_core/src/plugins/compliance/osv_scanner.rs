use crate::plugins::{ScannerPlugin, Capability, PluginMetadata, RiskLevel};
use crate::models::{TargetHost, Finding, Severity, Category, TargetType};
use crate::utils::tool_detection::detect_tool;
use async_trait::async_trait;
use anyhow::Result;
use tracing::info;
use std::process::Stdio;
use tokio::process::Command;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
struct OSVResult {
    results: Vec<OSVPackageResult>,
}

#[derive(Debug, Deserialize, Serialize)]
struct OSVPackageResult {
    packages: Vec<OSVPackage>,
}

#[derive(Debug, Deserialize, Serialize)]
struct OSVPackage {
    package: PackageInfo,
    vulnerabilities: Vec<OSVVulnerability>,
}

#[derive(Debug, Deserialize, Serialize)]
struct PackageInfo {
    name: String,
    version: String,
    ecosystem: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct OSVVulnerability {
    id: String,
    summary: Option<String>,
    details: Option<String>,
    modified: String,
    _published: Option<String>,
    _database_specific: Option<serde_json::Value>,
}

pub struct OSVScanner {
    binary_path: String,
}

impl Default for OSVScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl OSVScanner {
    pub fn new() -> Self {
        let path = detect_tool("osv-scanner");
        Self {
            binary_path: path,
        }
    }

    async fn scan_api(&self, name: &str, version: &str, ecosystem: &str) -> Result<Vec<Finding>> {
        let client = reqwest::Client::new();
        let payload = serde_json::json!({
            "package": {
                "name": name,
                "ecosystem": ecosystem,
            },
            "version": version,
        });

        let resp = client.post("https://api.osv.dev/v1/query")
            .json(&payload)
            .send()
            .await?;

        if !resp.status().is_success() {
            return Ok(Vec::new());
        }

        let res: serde_json::Value = resp.json().await?;
        let mut findings = Vec::new();
        
        if let Some(vulns) = res.get("vulns").and_then(|v| v.as_array()) {
            for vuln in vulns {
                let id = vuln.get("id").and_then(|v| v.as_str()).unwrap_or("Unknown");
                let summary = vuln.get("summary").and_then(|v| v.as_str()).unwrap_or("No summary");
                
                findings.push(Finding::new(
                    crate::models::FINDING_SCA_VULN,
                    Category::SCA,
                    Severity::High,
                    &format!("OSV API: Vulnerability in {}@{}: {}", name, version, summary),
                    vuln.clone()
                ).with_references(vec![format!("https://osv.dev/vulnerability/{}", id)]));
            }
        }

        Ok(findings)
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
            exploit_difficulty: crate::plugins::RiskLevel::Medium,
            blackarch_category: None,
            is_destructive: false,
            poc_mode: false, ..Default::default() }
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::SCA, Capability::SecurityAuditing]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability("osv-scanner").await)
    }

    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        info!("OSVScanner: launching scan against {}", target.host);

        let mut findings = Vec::new();
        let target_path = std::path::Path::new(&target.host);
        
        if !target_path.exists() {
            return Ok(findings);
        }

        // 1. Binary Scan
        if crate::utils::check_tool_availability("osv-scanner").await {
            let mut cmd = Command::new(&self.binary_path);
            cmd.arg("-r") // recursive
               .arg("--json")
               .arg(&target.host)
               .stdin(Stdio::null())
               .stdout(Stdio::piped())
               .stderr(Stdio::null());

            if let Ok(output) = cmd.output().await {
                if let Ok(res) = serde_json::from_slice::<OSVResult>(&output.stdout) {
                    for pkg_res in res.results {
                        for pkg in pkg_res.packages {
                            for vuln in pkg.vulnerabilities {
                                findings.push(Finding::new(
                                    crate::models::FINDING_SCA_VULN,
                                    Category::SCA,
                                    Severity::High,
                                    &format!("OSV (Binary): {}@{} - {}", pkg.package.name, pkg.package.version, vuln.summary.as_deref().unwrap_or("No summary")),
                                    serde_json::json!(vuln)
                                ).with_references(vec![format!("https://osv.dev/vulnerability/{}", vuln.id)]));
                            }
                        }
                    }
                }
            }
        } 
        
        // 2. API Fallback (if binary failed or results empty)
        if findings.is_empty() {
            // Attempt to parse package.json for basic dependencies
            let pkg_json_path = target_path.join("package.json");
            if pkg_json_path.exists() {
                if let Ok(content) = std::fs::read_to_string(pkg_json_path) {
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&content) {
                        if let Some(deps) = v.get("dependencies").and_then(|d| d.as_object()) {
                            for (name, version_req) in deps {
                                let version = version_req.as_str().unwrap_or("").trim_start_matches(['^', '~']);
                                if !version.is_empty() {
                                    if let Ok(mut api_findings) = self.scan_api(name, version, "npm").await {
                                        findings.append(&mut api_findings);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(findings)
    }
}
