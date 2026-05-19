use crate::plugins::{PluginMetadata, ScannerPlugin, Capability, RiskLevel};
use crate::models::{TargetHost, TargetType, Finding, findings::{Category, Severity}};
use crate::utils::tool_detection::check_tool_availability;
use crate::core::capability_layer::ScanLayer;
use async_trait::async_trait;
use anyhow::{Result, Context};
use std::env;
use tokio::process::Command;
use tracing::{info, warn};

pub struct KerbruteScanner {
    wordlist_path: Option<String>,
}

impl KerbruteScanner {
    pub fn new() -> Self {
        Self {
            wordlist_path: env::var("KERBRUTE_USERLIST").ok(),
        }
    }
}

impl Default for KerbruteScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ScannerPlugin for KerbruteScanner {
    fn name(&self) -> &'static str {
        "kerbrute"
    }

    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: "Kerbrute AD Enumeration".to_string(),
            description: "Performs Active Directory Kerberos Pre-Auth user enumeration".to_string(),
            target_type: TargetType::ActiveDirectory,
            risk_level: RiskLevel::Medium,
            layer: ScanLayer::Scanning,
            category: "ActiveDirectory".to_string(),
            expected_duration: std::time::Duration::from_secs(300),
            capabilities: vec![Capability::ActiveDirectory, Capability::BruteForce],
            cost: 2,
            mitre_attacks: vec!["T1087.002".to_string()], // Account Discovery: Domain Account
            exploit_difficulty: RiskLevel::Low,
            blackarch_category: Some("recon".to_string()),
            is_destructive: false,
            poc_mode: true, ..Default::default() }
    }

    fn capabilities(&self) -> Vec<Capability> {
        self.metadata().capabilities
    }

    async fn check_dependencies(&self) -> Result<bool> {
        Ok(check_tool_availability("kerbrute").await)
    }

    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        // Validation: Must be AD target or have port 88 open
        let has_port_88 = target.findings.iter().any(|f| {
            f.category == Category::NetworkPort 
            && f.evidence.primary.as_ref().is_some_and(|ev| {
                ev.data.get("port").and_then(|p| p.as_u64()) == Some(88)
            })
        });

        if target.target_type != TargetType::ActiveDirectory && !has_port_88 {
            return Ok(vec![]);
        }

        // Must have wordlist
        let wordlist = match &self.wordlist_path {
            Some(w) => w.clone(),
            None => {
                warn!("⚠️ Kerbrute skipping: KERBRUTE_USERLIST not set in env.");
                return Ok(vec![]);
            }
        };

        let domain = target.host.clone();
        
        // Pinned DC Address
        let dc_addr = target.target_addr().to_string();

        info!("🛡️ [Kerbrute] Enumerating Kerberos users for domain: {} via DC: {}", domain, dc_addr);

        let output = Command::new("kerbrute")
            .arg("userenum")
            .arg("-d").arg(&domain)
            .arg("--dc").arg(&dc_addr)
            .arg(&wordlist)
            .output()
            .await
            .context("Failed to execute kerbrute binary")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut findings = Vec::new();

        for line in stdout.lines() {
            if line.contains("[+] VALID USERNAME:") {
                if let Some(user) = line.split("VALID USERNAME:").nth(1) {
                    let user = user.trim();
                    let f = Finding::builder(
                        &format!("kerbrute_valid_user_{}", user),
                        Category::ExposedAsset,
                        Severity::Low,
                        &format!("Valid AD User Discovered: {}", user),
                    )
                    .with_evidence(serde_json::json!({
                        "username": user,
                        "domain": domain,
                        "dc": dc_addr,
                        "tool": "kerbrute"
                    }))
                    .build()
                    .with_mitre_attack(vec!["T1087.002".to_string()]);

                    findings.push(f);
                }
            }
        }

        if findings.is_empty() {
            info!("🛡️ [Kerbrute] No valid users found.");
        } else {
            info!("🛡️ [Kerbrute] Found {} valid AD users.", findings.len());
        }

        Ok(findings)
    }
}
