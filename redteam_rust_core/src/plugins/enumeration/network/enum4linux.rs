use crate::plugins::{PluginMetadata, ScannerPlugin, Capability, RiskLevel};
use crate::models::{TargetHost, TargetType, Finding, findings::{Category, Severity}};
use crate::core::capability_layer::ScanLayer;
use async_trait::async_trait;
use anyhow::{Result, Context};
use tokio::process::Command;
use tracing::{info, warn};
use crate::utils::tool_detection::check_tool_availability;


pub struct Enum4LinuxScanner;

impl Enum4LinuxScanner {
    pub fn new() -> Self {
        Self
    }
}

impl Default for Enum4LinuxScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ScannerPlugin for Enum4LinuxScanner {
    fn name(&self) -> &'static str {
        "enum4linux-ng"
    }

    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: "Enum4Linux-NG SMB Enumeration".to_string(),
            description: "Performs Active Directory/Windows SMB enumeration via enum4linux-ng".to_string(),
            target_type: TargetType::ActiveDirectory,
            risk_level: RiskLevel::Medium,
            layer: ScanLayer::Scanning,
            category: "ActiveDirectory".to_string(),
            expected_duration: std::time::Duration::from_secs(600),
            capabilities: vec![Capability::ActiveDirectory, Capability::ServiceDiscovery, Capability::InformationGathering],
            cost: 3,
            mitre_attacks: vec![
                "T1087".to_string(), // Account Discovery
                "T1039".to_string(), // Data from Network Shared Drive
                "T1135".to_string(), // Network Share Discovery
            ],
            exploit_difficulty: RiskLevel::Low,
            blackarch_category: Some("recon".to_string()),
            is_destructive: false,
            poc_mode: true, ..Default::default() }
    }

    fn capabilities(&self) -> Vec<Capability> {
        self.metadata().capabilities
    }

    async fn check_dependencies(&self) -> Result<bool> {
        Ok(check_tool_availability("enum4linux-ng").await)
    }

    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        // Trigger: AD/Windows target or port 139/445 open
        let has_smb_port = target.findings.iter().any(|f| {
            f.category == Category::NetworkPort 
            && f.evidence.primary.as_ref().is_some_and(|ev| {
                let port = ev.data.get("port").and_then(|p| p.as_u64());
                port == Some(139) || port == Some(445)
            })
        });

        if target.target_type != TargetType::ActiveDirectory 
            && target.target_type != TargetType::Windows 
            && !has_smb_port {
            return Ok(vec![]);
        }

        let addr = target.target_addr().to_string();
        let temp_dir = std::env::temp_dir();
        let json_path = temp_dir.join(format!("enum4linux_{}.json", addr.replace(".", "_")));

        info!("🛡️ [Enum4Linux-NG] Enumerating SMB for target: {}", addr);

        let output = Command::new("enum4linux-ng")
            .arg("-A")
            .arg("-oJ").arg(&json_path)
            .arg(&addr)
            .output()
            .await
            .context("Failed to execute enum4linux-ng")?;

        if !output.status.success() {
            warn!("⚠️ [Enum4Linux-NG] Process exited with error: {}", String::from_utf8_lossy(&output.stderr));
        }

        let mut findings = Vec::new();

        if let Ok(content) = tokio::fs::read_to_string(&json_path).await {
            if let Ok(data) = serde_json::from_str::<serde_json::Value>(&content) {
                // Parse Users (Object keyed by RID)
                if let Some(users_obj) = data.get("users").and_then(|u| u.as_object()) {
                    for (rid, user) in users_obj {
                        if let Some(name) = user.get("username").and_then(|n| n.as_str()) {
                            findings.push(
                                Finding::builder(
                                    &format!("enum4linux_user_{}", name),
                                    Category::ExposedAsset,
                                    Severity::Low,
                                    &format!("SMB User Discovered: {} (RID: {})", name, rid),
                                )
                                .with_evidence(user.clone())
                                .build()
                                .with_mitre_attack(vec!["T1087".to_string()])
                            );
                        }
                    }
                }

                // Parse Shares (Object keyed by Name)
                if let Some(shares_obj) = data.get("shares").and_then(|s| s.as_object()) {
                    for (name, share) in shares_obj {
                        findings.push(
                            Finding::builder(
                                &format!("enum4linux_share_{}", name),
                                Category::ExposedAsset,
                                Severity::Low,
                                &format!("SMB Share Discovered: {}", name),
                            )
                            .with_evidence(share.clone())
                            .build()
                            .with_mitre_attack(vec!["T1135".to_string()])
                        );
                    }
                }
                
                // OS Info / Domain
                if let Some(os_info) = data.get("os_info") {
                    findings.push(
                        Finding::builder(
                            "enum4linux_os_info",
                            Category::TechnologyStack,
                            Severity::Info,
                            "SMB OS Fingerprint Captured",
                        )
                        .with_evidence(os_info.clone())
                        .build()
                    );
                }
            }
            // Cleanup
            let _ = tokio::fs::remove_file(&json_path).await;
        }

        Ok(findings)
    }
}
