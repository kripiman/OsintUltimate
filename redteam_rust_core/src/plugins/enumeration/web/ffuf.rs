use crate::plugins::{ScannerPlugin, Capability, RiskLevel};
use crate::models::{TargetHost, Finding, Severity, Category};
use crate::utils::tool_detection::detect_tool;
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::{info, warn};
use std::process::Stdio;
use tokio::process::Command;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct FfufResult {
    results: Vec<FfufItem>,
}

#[derive(Debug, Deserialize)]
struct FfufItem {
    url: String,
    status: u16,
    length: u64,
    words: u64,
}

pub struct FfufScanner {
    binary_path: String,
    wordlist: String,
}

impl FfufScanner {
    pub fn new(wordlist: Option<String>) -> Self {
        let path = detect_tool("ffuf");
        Self {
            binary_path: path,
            wordlist: wordlist.unwrap_or_else(|| "/usr/share/wordlists/dirb/common.txt".into()),
        }
    }
}

#[async_trait]
impl ScannerPlugin for FfufScanner {
    fn name(&self) -> &'static str {
        crate::models::PLUGIN_FFUF
    }

    
        fn metadata(&self) -> crate::plugins::PluginMetadata {
        crate::plugins::PluginMetadata {
            name: self.name().to_string(),
            description: "Automated security analysis using this plugin.".to_string(),
            target_type: crate::plugins::TargetType::Web,
            risk_level: crate::plugins::RiskLevel::Medium,
            layer: crate::core::capability_layer::ScanLayer::Scanning,
            expected_duration: std::time::Duration::from_secs(300),
            capabilities: self.capabilities(),
            cost: 5,
            category: "Enumeration".to_string(),
            mitre_attacks: vec!["T1595".to_string()],
            exploit_difficulty: RiskLevel::Low,
            blackarch_category: Some("webapp".to_string()),
            is_destructive: false,
            poc_mode: true, ..Default::default() }
    }
    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::WebFuzzing]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability("ffuf").await)
    }


    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        info!("FfufScanner: launching scan against {}", target.host);

        let url = if target.host.starts_with("http") {
            target.host.clone()
        } else {
            format!("http://{}", target.host)
        };

        let temp_file = tempfile::NamedTempFile::new().context("Failed to create temp file for Ffuf")?;
        let temp_path = temp_file.path().to_string_lossy().to_string();

        let mut child = Command::new(&self.binary_path)
            .arg("-u").arg(format!("{}/FUZZ", url))
            .arg("-w").arg(&self.wordlist)
            .arg("-of").arg("json")
            .arg("-o").arg(&temp_path)
            .arg("-s") // Silent
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("Failed to spawn ffuf")?;

        let status = child.wait().await.context("Failed to wait for ffuf")?;

        if !status.success() {
            warn!("Ffuf failed on {}", target.host);
        }

        let mut findings = Vec::new();

        if let Ok(content) = tokio::fs::read_to_string(&temp_path).await {
            if let Ok(res) = serde_json::from_str::<FfufResult>(&content) {
                for item in res.results {
                    findings.push(Finding::new(
                        &format!("FFUF-RES-{}", item.status),
                        Category::Recon,
                        Severity::Info,
                        &format!("Discovered resource: {} (Status: {}, Length: {})", item.url, item.status, item.length),
                        serde_json::json!({
                            "url": item.url,
                            "status": item.status,
                            "length": item.length,
                            "words": item.words,
                        })
                    ));
                }
            }
        }

        Ok(findings)
    }
}
