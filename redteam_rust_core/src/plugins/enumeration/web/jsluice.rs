use crate::plugins::{ScannerPlugin, Capability, TargetType, RiskLevel};
use crate::models::{TargetHost, Finding, Severity, Category};
use crate::utils::{detect_tool, check_tool_availability};
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::{info, warn, error};
use std::process::Stdio;
use tokio::process::Command;
use crate::models::constants::*;
use std::io::Write;

pub struct JsluiceScanner {
    binary_path: String,
}

impl Default for JsluiceScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl JsluiceScanner {
    pub fn new() -> Self {
        let path = detect_tool("jsluice");
        Self {
            binary_path: path,
        }
    }
}

#[async_trait]
impl ScannerPlugin for JsluiceScanner {
    fn name(&self) -> &'static str {
        PLUGIN_JSLUICE
    }

    fn metadata(&self) -> crate::plugins::PluginMetadata {
        crate::plugins::PluginMetadata {
            name: self.name().to_string(),
            description: "Extract URLs and secrets from JavaScript files using AST parsing (BishopFox).".to_string(),
            target_type: TargetType::Web,
            risk_level: RiskLevel::Low,
            layer: crate::core::capability_layer::ScanLayer::Scanning,
            expected_duration: std::time::Duration::from_secs(60),
            capabilities: vec![Capability::VulnerabilityScanning, Capability::InformationGathering],
            cost: 2,
            category: "Enumeration".to_string(),
            mitre_attacks: vec!["T1592".to_string(), "T1595".to_string()],
            exploit_difficulty: RiskLevel::Low,
            blackarch_category: Some("webapp".to_string()),
            is_destructive: false,
            poc_mode: true, ..Default::default() }
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::VulnerabilityScanning, Capability::InformationGathering]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        Ok(check_tool_availability("jsluice").await)
    }

    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        info!("JsluiceScanner: scanning target {}", target.host);
        
        // Sanity check binary existence
        if !self.check_dependencies().await.unwrap_or(false) {
            warn!("JsluiceScanner: jsluice binary not found. Skipping.");
            return Ok(Vec::new());
        }

        let mut findings = Vec::new();

        // 1. Identify JS URLs from previous findings (e.g. from Katana)
        let mut js_urls = std::collections::HashSet::new();
        
        for f in target.findings.iter() {
            if let Some(ev) = &f.evidence.primary {
                // Katana/Gauplus format: "urls" array
                if let Some(urls) = ev.data.get("urls").and_then(|u| u.as_array()) {
                    for u in urls {
                        if let Some(url_str) = u.as_str() {
                            if is_js_file(url_str) {
                                js_urls.insert(url_str.to_string());
                            }
                        }
                    }
                }
                // Generic single "url", "uri", "endpoint", or "path" field
                for key in ["url", "uri", "endpoint", "path"] {
                    if let Some(url_str) = ev.data.get(key).and_then(|u| u.as_str()) {
                         if is_js_file(url_str) {
                            js_urls.insert(url_str.to_string());
                        }
                    }
                }
            }
        }

        // Special case: if target host itself is a JS file
        if is_js_file(&target.host) {
            js_urls.insert(target.host.clone());
        }

        if js_urls.is_empty() {
            info!("JsluiceScanner: no JS files found in previous findings for {}", target.host);
            return Ok(findings);
        }

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()?;

        for url in js_urls {
            info!("JsluiceScanner: analyzing JS file {}", url);
            
            // Download to temp file
            let response = match client.get(&url).send().await {
                Ok(resp) => resp,
                Err(e) => {
                    warn!("JsluiceScanner: failed to download {}: {}", url, e);
                    continue;
                }
            };

            let content = match response.text().await {
                Ok(t) => t,
                Err(e) => {
                    warn!("JsluiceScanner: failed to read content of {}: {}", url, e);
                    continue;
                }
            };

            let mut temp = match tempfile::NamedTempFile::new() {
                Ok(t) => t,
                Err(e) => {
                    error!("JsluiceScanner: failed to create temp file: {}", e);
                    continue;
                }
            };
            
            if let Err(e) = temp.write_all(content.as_bytes()) {
                error!("JsluiceScanner: failed to write to temp file: {}", e);
                continue;
            }
            
            let temp_path = temp.path().to_string_lossy().to_string();

            // Analyze Secrets
            match self.run_jsluice_secrets(&url, &temp_path).await {
                Ok(mut secret_findings) => findings.append(&mut secret_findings),
                Err(e) => error!("JsluiceScanner: secrets error for {}: {}", url, e),
            }

            // Analyze URLs/Endpoints
            match self.run_jsluice_urls(&url, &temp_path).await {
                Ok(mut url_findings) => findings.append(&mut url_findings),
                Err(e) => error!("JsluiceScanner: urls error for {}: {}", url, e),
            }
        }

        Ok(findings)
    }
}

impl JsluiceScanner {
    async fn run_jsluice_secrets(&self, source_url: &str, file_path: &str) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        let output = tokio::time::timeout(std::time::Duration::from_secs(30), Command::new(&self.binary_path)
            .arg("secrets")
            .arg(file_path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output())
            .await
            .context("Jsluice secrets execution timed out")?
            .context("Failed to run jsluice secrets")?;

        if !output.status.success() {
            return Ok(findings);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(line) {
                let kind = json.get("kind").and_then(|k| k.as_str()).unwrap_or("unknown");
                findings.push(Finding::new(
                    FINDING_JS_SECRET,
                    Category::CredentialLeak,
                    Severity::High,
                    &format!("Potential {} found in JavaScript file: {}", kind, source_url),
                    serde_json::json!({
                        "source_url": source_url,
                        "secret_info": json,
                    })
                ));
            }
        }

        Ok(findings)
    }

    async fn run_jsluice_urls(&self, source_url: &str, file_path: &str) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        let output = tokio::time::timeout(std::time::Duration::from_secs(30), Command::new(&self.binary_path)
            .arg("urls")
            .arg(file_path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output())
            .await
            .context("Jsluice urls execution timed out")?
            .context("Failed to run jsluice urls")?;

        if !output.status.success() {
            return Ok(findings);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut discovered_urls = Vec::new();
        for line in stdout.lines() {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(line) {
                if let Some(discovered) = json.get("url").and_then(|u| u.as_str()) {
                    discovered_urls.push(discovered.to_string());
                }
            }
        }

        if !discovered_urls.is_empty() {
            findings.push(Finding::new(
                FINDING_JS_ENDPOINT,
                Category::Recon,
                Severity::Info,
                &format!("Discovered {} new endpoints in {}", discovered_urls.len(), source_url),
                serde_json::json!({
                    "source_url": source_url,
                    "discovered_endpoints": discovered_urls,
                })
            ));
        }

        Ok(findings)
    }
}

fn is_js_file(url: &str) -> bool {
    url.ends_with(".js") || url.contains(".js?") || url.contains(".js#")
}
