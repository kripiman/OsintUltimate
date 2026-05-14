use crate::plugins::{ScannerPlugin, Capability, PluginMetadata, RiskLevel, TargetType};
use crate::models::{TargetHost, Finding, Severity, Category, constants::*};
use std::sync::atomic::{AtomicBool, Ordering};

static EXECUTED: AtomicBool = AtomicBool::new(false);
use crate::utils::{detect_tool, check_tool_availability};
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::{info, warn};
use std::process::Stdio;
use tokio::process::Command;

pub struct AzureHoundScanner {
    binary_path: String,
}

impl Default for AzureHoundScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl AzureHoundScanner {
    pub fn new() -> Self {
        let path = detect_tool("azurehound");
        Self {
            binary_path: path,
        }
    }

    fn get_creds(&self) -> (Option<String>, Option<String>, Option<String>) {
        (
            std::env::var("AZURE_CLIENT_ID").ok(),
            std::env::var("AZURE_TENANT_ID").ok(),
            std::env::var("AZURE_CLIENT_SECRET").ok(),
        )
    }
}

#[async_trait]
impl ScannerPlugin for AzureHoundScanner {
    fn name(&self) -> &'static str {
        "azurehound"
    }

    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: self.name().to_string(),
            description: "AzureHound: Azure AD / Entra ID attack surface mapping (BloodHound for Cloud).".to_string(),
            target_type: TargetType::Host,
            risk_level: RiskLevel::High,
            layer: crate::core::capability_layer::ScanLayer::PostExploitation,
            category: "Windows".to_string(),
            expected_duration: std::time::Duration::from_secs(600),
            capabilities: vec![Capability::IAMAssessment, Capability::ActiveDirectory],
            cost: 10,
            mitre_attacks: vec!["T1087.004".to_string()],
            exploit_difficulty: RiskLevel::High,
            blackarch_category: Some("recon".to_string()),
            is_destructive: false,
            poc_mode: false,
            ..Default::default()
        }
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::IAMAssessment, Capability::ActiveDirectory]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        if !check_tool_availability("azurehound").await {
            return Ok(false);
        }
        let (id, tenant, secret) = self.get_creds();
        Ok(id.is_some() && tenant.is_some() && secret.is_some())
    }
    async fn scan(&self, _target: &TargetHost) -> Result<Vec<Finding>> {
        let (client_id, tenant_id, client_secret) = self.get_creds();
        let (client_id, tenant_id, client_secret) = match (client_id, tenant_id, client_secret) {
            (Some(id), Some(t), Some(s)) => (id, t, s),
            _ => {
                warn!("AzureHound: Missing credentials (AZURE_CLIENT_ID, AZURE_TENANT_ID, AZURE_CLIENT_SECRET). Skipping.");
                return Ok(Vec::new());
            }
        };

        // [N-2] Flag set ONLY after confirming credentials present
        if EXECUTED.swap(true, Ordering::SeqCst) {
            return Ok(Vec::new());
        }

        info!("AzureHound: Starting Azure AD collection for tenant {}", tenant_id);

        let output = tokio::time::timeout(std::time::Duration::from_secs(600), Command::new(&self.binary_path)
            .arg("list")
            .arg("--tenant-id").arg(&tenant_id)
            .arg("--client-id").arg(&client_id)
            .arg("--client-secret").arg(&client_secret)
            .arg("--json")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output())
            .await
            .context("AzureHound execution timed out")?
            .context("Failed to run azurehound")?;

        let mut findings = Vec::new();
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            
            // [M-2] Robust JSON parsing for high-value roles
            let mut high_priv = false;
            if let Ok(json_output) = serde_json::from_str::<serde_json::Value>(&stdout) {
                if let Some(nodes) = json_output.as_array() {
                    for node in nodes {
                        if let Some(props) = node.get("Properties") {
                            let name = props.get("name").and_then(|n| n.as_str()).unwrap_or("");
                            if name.contains("Global Administrator") || name.contains("Privileged Role Administrator") {
                                high_priv = true;
                                break;
                            }
                        }
                    }
                }
            } else if stdout.contains("Global Administrator") || stdout.contains("Privileged Role Administrator") {
                // Fallback to string matching if JSON parsing fails for some reason
                high_priv = true;
            }

            if high_priv {
                findings.push(Finding::new(
                    FINDING_AZURE_HIGH_PRIVILEGE,
                    Category::Windows,
                    Severity::High,
                    "AzureHound: High-privilege Azure AD roles detected.",
                    serde_json::json!({
                        "tenant_id": tenant_id,
                        "raw_output_snippet": stdout.chars().take(1000).collect::<String>(),
                    })
                ).with_tactical_path("Analyze the attack path in BloodHound to identify potential privilege escalation or lateral movement opportunities in Entra ID."));
            }
            
            // [H-3] Also emit a general discovery finding using constant
            findings.push(Finding::new(
                FINDING_AZURE_RECON_COMPLETE,
                Category::Recon,
                Severity::Info,
                &format!("AzureHound: Completed collection for tenant {}", tenant_id),
                serde_json::json!({ "tenant_id": tenant_id, "output_size": stdout.len() })
            ));
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!("AzureHound failed: {}", stderr);
        }

        Ok(findings)
    }
}
