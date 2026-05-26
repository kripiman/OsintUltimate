use crate::plugins::{ScannerPlugin, Capability};
use crate::models::{TargetHost, Finding, Severity, Category};
use crate::utils::tool_detection::detect_tool;
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::{info, warn};
use std::process::Stdio;
use tokio::process::Command;

pub struct Wafw00fScanner {
    binary_path: String,
}

impl Default for Wafw00fScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl Wafw00fScanner {
    pub fn new() -> Self {
        let path = detect_tool("wafw00f");
        Self { binary_path: path }
    }
}

#[async_trait]
impl ScannerPlugin for Wafw00fScanner {
    fn name(&self) -> &'static str {
        crate::models::PLUGIN_WAFW00F
    }

    fn metadata(&self) -> crate::plugins::PluginMetadata {
        crate::plugins::PluginMetadata {
            name: self.name().to_string(),
            description: "WAF fingerprinting via wafw00f — detects 150+ WAF signatures.".to_string(),
            target_type: crate::plugins::TargetType::Web,
            risk_level: crate::plugins::RiskLevel::Safe,
            layer: crate::core::capability_layer::ScanLayer::Discovery,
            expected_duration: std::time::Duration::from_secs(60),
            capabilities: self.capabilities(),
            cost: 3,
            category: "Reconnaissance".to_string(),
            mitre_attacks: vec![],
            exploit_difficulty: crate::plugins::RiskLevel::Safe,
            blackarch_category: None,
            is_destructive: false,
            poc_mode: false,
            ..Default::default()
        }
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::WafDetection]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability("wafw00f").await)
    }

    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        let url = if target.host.starts_with("http") {
            target.host.clone()
        } else {
            format!("https://{}", target.host)
        };

        info!("Wafw00fScanner: fingerprinting WAF for {}", url);

        let tmpfile = format!("/tmp/wafw00f_{}_{}.json",
            target.host.replace(|c: char| !c.is_alphanumeric(), "_"),
            &uuid::Uuid::new_v4().to_string().replace('-', "")[..8]
        );

        let child = Command::new(&self.binary_path)
            .arg("-a")
            .arg(&url)
            .arg("--format").arg("json")
            .arg("-o").arg(&tmpfile)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .context("Failed to spawn wafw00f")?;

        let _output = child.wait_with_output().await.context("Failed to wait for wafw00f")?;

        let mut findings = Vec::new();

        match tokio::fs::read_to_string(&tmpfile).await {
            Ok(content) => {
                let _ = tokio::fs::remove_file(&tmpfile).await;
                if let Ok(entries) = serde_json::from_str::<Vec<Wafw00fEntry>>(&content) {
                    for entry in entries {
                        if entry.detected {
                            findings.push(Finding::new(
                                &format!("WAF-DETECTED-{}", sanitize_id(&entry.firewall)),
                                Category::WafDetected,
                                Severity::Info,
                                &format!("WAF detected: {} ({})", entry.firewall, entry.manufacturer),
                                serde_json::json!({
                                    "waf_name": entry.firewall,
                                    "manufacturer": entry.manufacturer,
                                    "trigger_url": entry.trigger_url,
                                    "target_url": entry.url,
                                })
                            ));
                        }
                    }
                } else {
                    warn!("Wafw00fScanner: failed to parse JSON output for {}", url);
                }
            }
            Err(e) => {
                warn!("Wafw00fScanner: failed to read output file for {}: {}", url, e);
            }
        }

        info!("Wafw00fScanner: found {} WAF signatures for {}", findings.len(), url);
        Ok(findings)
    }
}

#[derive(Debug, serde::Deserialize)]
struct Wafw00fEntry {
    detected: bool,
    firewall: String,
    manufacturer: String,
    #[serde(rename = "trigger_url")]
    trigger_url: String,
    url: String,
}

fn sanitize_id(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_alphanumeric() || c == '-' { c } else { '-' })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_id() {
        assert_eq!(sanitize_id("Cloudflare Inc."), "Cloudflare-Inc-");
        assert_eq!(sanitize_id("AWS WAF"), "AWS-WAF");
    }

    #[test]
    fn test_wafw00f_json_parse() {
        let json = r#"[{"detected":true,"firewall":"Cloudflare","manufacturer":"Cloudflare Inc.","trigger_url":"https://example.com/?x=<script>","url":"https://example.com"}]"#;
        let entries: Vec<Wafw00fEntry> = serde_json::from_str(json).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].firewall, "Cloudflare");
        assert!(entries[0].detected);
    }

    #[test]
    fn test_wafw00f_json_empty() {
        let json = r#"[]"#;
        let entries: Vec<Wafw00fEntry> = serde_json::from_str(json).unwrap();
        assert!(entries.is_empty());
    }
}
