use crate::plugins::{ScannerPlugin, Capability, PluginMetadata, RiskLevel, TargetType};
use crate::models::{TargetHost, Finding, Severity, Category, constants::*};
use std::sync::atomic::{AtomicBool, Ordering};

static EXECUTED: AtomicBool = AtomicBool::new(false);
use crate::utils::{detect_tool, check_tool_availability};
use async_trait::async_trait;
use anyhow::Result;
use tracing::{info, warn};
use std::process::Stdio;
use tokio::process::Command;

pub struct RoadReconScanner {
    binary_path: String,
}

impl Default for RoadReconScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl RoadReconScanner {
    pub fn new() -> Self {
        let path = detect_tool("roadrecon");
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
impl ScannerPlugin for RoadReconScanner {
    fn name(&self) -> &'static str {
        "roadrecon"
    }

    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: self.name().to_string(),
            description: "ROADrecon: Azure AD exploration and misconfiguration discovery tool.".to_string(),
            target_type: TargetType::Host,
            risk_level: RiskLevel::High,
            layer: crate::core::capability_layer::ScanLayer::PostExploitation,
            category: "Windows".to_string(),
            expected_duration: std::time::Duration::from_secs(600),
            capabilities: vec![Capability::IAMAssessment],
            cost: 8,
            mitre_attacks: vec!["T1087.004".to_string()],
            exploit_difficulty: RiskLevel::Medium,
            blackarch_category: Some("recon".to_string()),
            is_destructive: false,
            poc_mode: false,
            ..Default::default()
        }
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::IAMAssessment]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        if !check_tool_availability("roadrecon").await {
            return Ok(false);
        }
        let (id, tenant, secret) = self.get_creds();
        Ok(id.is_some() && tenant.is_some() && secret.is_some())
    }
    async fn scan(&self, _target: &TargetHost) -> Result<Vec<Finding>> {
        let (client_id, tenant_id, client_secret) = self.get_creds();
        let (client_id, tenant_id, client_secret) = match (client_id, tenant_id, client_secret) {
            (Some(id), Some(t), Some(s)) => (id, t, s),
            _ => return Ok(Vec::new()),
        };

        // [N-2] Flag set ONLY after confirming credentials present
        if EXECUTED.swap(true, Ordering::SeqCst) {
            return Ok(Vec::new());
        }

        info!("RoadReconScanner: Starting Azure AD collection...");

        // 1. Auth
        let auth_status = Command::new(&self.binary_path)
            .arg("auth")
            .arg("--client-id").arg(&client_id)
            .arg("--tenant").arg(&tenant_id)
            .arg("--client-secret").arg(&client_secret)
            .status()
            .await?;

        if !auth_status.success() {
            warn!("RoadReconScanner: Authentication failed.");
            return Ok(Vec::new());
        }

        // 2. Gather
        let gather_status = Command::new(&self.binary_path)
            .arg("gather")
            .status()
            .await?;

        if !gather_status.success() {
            warn!("RoadReconScanner: Gather failed.");
            return Ok(Vec::new());
        }

        // 3. Dump
        let output = Command::new(&self.binary_path)
            .arg("plugin")
            .arg("policies") // Example: Dump policies
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await?;

        let mut findings = Vec::new();
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            
            if stdout.contains("Conditional Access") || stdout.contains("Policy") {
                findings.push(Finding::new(
                    FINDING_AZURE_POLICIES_DUMPED,
                    Category::Windows,
                    Severity::Medium,
                    "RoadRecon: Azure AD policies and misconfigurations discovered.",
                    serde_json::json!({
                        "tenant_id": tenant_id,
                        "raw_output": stdout.chars().take(2000).collect::<String>(),
                    })
                ));
            }
        }

        Ok(findings)
    }
}
