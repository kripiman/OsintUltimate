use crate::plugins::{ScannerPlugin, Capability, PluginMetadata, RiskLevel, TargetType};
use crate::models::{TargetHost, Finding, Severity, Category, PLUGIN_CAIDO};
use crate::core::capability_layer::ScanLayer;
use crate::utils::tool_detection::detect_tool;
use async_trait::async_trait;
use anyhow::{Result, Context, anyhow};
use tracing::{info, warn, debug};
use std::time::Duration;
use std::sync::Arc;
use tokio::process::{Command, Child};
use tokio::sync::Mutex;

use serde_json::json;

pub struct CaidoScanner {
    api_key: Option<String>,
    api_url: String,
    binary_path: String,
    process: Arc<Mutex<Option<Child>>>,
    proxy_manager: Arc<crate::utils::proxy::ProxyManager>,
}

impl CaidoScanner {
    pub fn new(config: &crate::utils::config::Config, pm: Arc<crate::utils::proxy::ProxyManager>) -> Self {
        Self {
            api_key: config.caido_api_key.clone(),
            api_url: config.caido_api_url.clone(),
            binary_path: detect_tool("caido-cli"),
            process: Arc::new(Mutex::new(None)),
            proxy_manager: pm,
        }
    }

    async fn ensure_instance(&self) -> Result<()> {
        let mut proc_guard = self.process.lock().await;
        if proc_guard.is_some() {
            // Check if still running
            if let Ok(None) = proc_guard.as_mut().unwrap().try_wait() {
                return Ok(());
            }
        }

        // Try to connect first - maybe it's already running manually
        if self.check_connection().await {
            debug!("Caido instance already running and responding.");
            return Ok(());
        }

        info!("🛡️ SENTINEL: Starting Managed Caido instance (Headless Mode)...");
        let child = Command::new(&self.binary_path)
            .arg("daemon")
            .arg("--listen")
            .arg(self.api_url.replace("http://", "").replace("/graphql", ""))
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .context("Failed to spawn caido-cli")?;

        *proc_guard = Some(child);

        // Wait for readiness
        for i in 0..10 {
            tokio::time::sleep(Duration::from_secs(1)).await;
            if self.check_connection().await {
                info!("✅ Caido Sentinel ready after {}s", i + 1);
                return Ok(());
            }
        }

        Err(anyhow!("Caido failed to start or respond within timeout"))
    }

    async fn check_connection(&self) -> bool {
        let host = url::Url::parse(&self.api_url).map(|u| u.host_str().unwrap_or("localhost").to_string()).unwrap_or_else(|_| "localhost".to_string());
        
        let client = if host == "localhost" || host == "127.0.0.1" {
            match self.proxy_manager.get_localhost_client(&host) {
                Ok((_, c)) => c,
                Err(_) => return false,
            }
        } else {
            match self.proxy_manager.get_client_fail_closed(&host) {
                Ok((_, c)) => c,
                Err(_) => return false,
            }
        };

        let query = json!({
            "query": "{ viewer { id } }"
        });

        let mut request = client.post(&self.api_url).json(&query);
        if let Some(key) = &self.api_key {
            request = request.header("Authorization", format!("Bearer {}", key));
        }

        request.send().await.map(|r| r.status().is_success()).unwrap_or(false)
    }

    async fn graphql_query(&self, query: serde_json::Value) -> Result<serde_json::Value> {
        let host = url::Url::parse(&self.api_url).map(|u| u.host_str().unwrap_or("localhost").to_string()).unwrap_or_else(|_| "localhost".to_string());
        
        let client = if host == "localhost" || host == "127.0.0.1" {
            self.proxy_manager.get_localhost_client(&host).map(|(_, c)| c)?
        } else {
            let (_, c) = self.proxy_manager.get_client_fail_closed(&host)?;
            c
        };

        let mut request = client.post(&self.api_url).json(&query);
        
        if let Some(key) = &self.api_key {
            request = request.header("Authorization", format!("Bearer {}", key));
        }

        let resp = request.send().await?;
        if !resp.status().is_success() {
            return Err(anyhow!("Caido API returned status {}", resp.status()));
        }

        Ok(resp.json().await?)
    }

    async fn create_project_if_needed(&self, domain: &str) -> Result<String> {
        let project_name = format!("Mimikri_{}", domain.replace('.', "_"));
        
        // 1. List projects to see if it exists
        let query = json!({
            "query": "query { projects { nodes { id name } } }"
        });
        let data = self.graphql_query(query).await?;
        
        if let Some(projects) = data.get("data").and_then(|d| d.get("projects")).and_then(|p| p.get("nodes")).and_then(|n| n.as_array()) {
            for p in projects {
                if p.get("name").and_then(|n| n.as_str()) == Some(&project_name) {
                    return Ok(p.get("id").and_then(|i| i.as_str()).unwrap_or_default().to_string());
                }
            }
        }

        // 2. Create project
        debug!("Creating new Caido project: {}", project_name);
        let mutation = json!({
            "query": "mutation($name: String!) { createProject(name: $name) { project { id } } }",
            "variables": { "name": project_name }
        });
        let resp = self.graphql_query(mutation).await?;
        let id = resp.get("data").and_then(|d| d.get("createProject")).and_then(|c| c.get("project")).and_then(|p| p.get("id")).and_then(|i| i.as_str())
            .ok_or_else(|| anyhow!("Failed to extract created project ID from Caido"))?;
            
        Ok(id.to_string())
    }
}

#[async_trait]
impl ScannerPlugin for CaidoScanner {
    fn name(&self) -> &'static str {
        PLUGIN_CAIDO
    }

    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: self.name().to_string(),
            description: "Sentinel Caido Integrator: Automated web security auditing via Managed Headless Caido instance (Optimized for Student/Bug Bounty workflows).".to_string(),
            target_type: TargetType::Web,
            risk_level: RiskLevel::Medium,
            layer: ScanLayer::Exploitation,
            expected_duration: Duration::from_secs(600),
            capabilities: vec![Capability::VulnerabilityScanning, Capability::ApiSecurity],
            cost: 4,
            category: "Verification".to_string(),
            ..Default::default()
        }
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::VulnerabilityScanning, Capability::ApiSecurity]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability("caido-cli").await)
    }

    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        self.ensure_instance().await?;
        
        let project_id = self.create_project_if_needed(&target.host).await?;
        info!("🔱 SENTINEL: Caido project {} active for {}", project_id, target.host);

        // V14.1: Submit the target for active auditing via GraphQL mutation
        let target_url = if target.host.starts_with("http") { target.host.clone() } else { format!("https://{}", target.host) };
        let scan_mutation = json!({
            "query": "mutation($projectId: ID!, $url: String!) { startScan(projectId: $projectId, url: $url) { scan { id } } }",
            "variables": { "projectId": project_id, "url": target_url }
        });
        
        match self.graphql_query(scan_mutation).await {
            Ok(_) => info!("🚀 V14.1: Caido active scan triggered for {}", target.host),
            Err(e) => warn!("⚠️ Caido: Scan trigger failed (Check mutation schema): {}", e),
        }

        // V14.1: Polling with backoff for findings
        let mut findings = Vec::new();
        let query = json!({
            "query": "query { findings { nodes { id title description severity } } }"
        });

        info!("⏳ V14.1: Polling Caido for results (30s timeout)...");
        for _ in 0..6 { // 6 * 5s = 30s
            tokio::time::sleep(Duration::from_secs(5)).await;
            
            if let Ok(data) = self.graphql_query(query.clone()).await {
                if let Some(nodes) = data.get("data").and_then(|d| d.get("findings")).and_then(|f| f.get("nodes")).and_then(|n| n.as_array()) {
                    if !nodes.is_empty() {
                        for node in nodes {
                            let sev_str = node.get("severity").and_then(|s| s.as_str()).unwrap_or("info");
                            let severity = match sev_str.to_lowercase().as_str() {
                                "high" => Severity::High,
                                "medium" => Severity::Medium,
                                "low" => Severity::Low,
                                _ => Severity::Info,
                            };

                            findings.push(Finding::new(
                                &format!("CAIDO-{}", node.get("id").and_then(|i| i.as_str()).unwrap_or("UNK")),
                                Category::Vulnerability,
                                severity,
                                node.get("title").and_then(|t| t.as_str()).unwrap_or("Caido Finding"),
                                node.clone()
                            ).with_tactical_path(node.get("description").and_then(|d| d.as_str()).unwrap_or("No details provided")));
                        }
                        break; // Exit polling loop if we found anything
                    }
                }
            }
        }

        info!("✅ Caido audit complete for {}: recovered {} findings", target.host, findings.len());
        Ok(findings)
    }
}
