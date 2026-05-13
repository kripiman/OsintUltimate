use crate::plugins::{DiscoveryPlugin, Capability, GlobalConfig, DiscoveryResult};
use crate::models::TargetHost;
use crate::utils::tool_detection::detect_tool;
use async_trait::async_trait;
use anyhow::Result;
use tracing::{info, warn};
use std::process::Stdio;
use crate::utils::executor::ExecutorMode;

pub struct BBScopeScanner {
    binary_path: String,
    h1_username: Option<String>,
    h1_api_key: Option<String>,
    bugcrowd_api_key: Option<String>,
    intigriti_token: Option<String>,
}

impl BBScopeScanner {
    pub fn new<M: ExecutorMode>(config: &GlobalConfig<M>) -> Self {
        let path = detect_tool("bbscope");
        Self {
            binary_path: path,
            h1_username: config.h1_username.clone(),
            h1_api_key: config.h1_api_key.clone(),
            bugcrowd_api_key: config.bugcrowd_api_key.clone(),
            intigriti_token: config.intigriti_token.clone(),
        }
    }
}

#[async_trait]
impl DiscoveryPlugin for BBScopeScanner {
    fn name(&self) -> &'static str {
        crate::models::PLUGIN_BBSCOPE
    }

    fn metadata(&self) -> crate::plugins::PluginMetadata {
        crate::plugins::PluginMetadata {
            name: self.name().to_string(),
            description: "bbscope: Extract scope from Bug Bounty platforms (H1, Bugcrowd, Intigriti).".to_string(),
            target_type: crate::plugins::TargetType::Osint,
            risk_level: crate::plugins::RiskLevel::Safe,
            layer: crate::core::capability_layer::ScanLayer::Passive,
            expected_duration: std::time::Duration::from_secs(600),
            capabilities: self.capabilities(),
            cost: 10,
            category: "Reconnaissance".to_string(),
            mitre_attacks: vec![],
            exploit_difficulty: crate::plugins::RiskLevel::Safe,
            blackarch_category: None,
            is_destructive: false,
            poc_mode: false, ..Default::default() }
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::ScopeExtraction]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability("bbscope").await)
    }

    async fn discover(&self, _target: &TargetHost) -> Result<Vec<DiscoveryResult>> {
        info!("BBScopeScanner: launching scope extraction");

        let mut discovered = Vec::new();

        // 1. HackerOne
        if let (Some(user), Some(key)) = (&self.h1_username, &self.h1_api_key) {
            if let Ok(results) = self.run_bbscope("h1", Some(user), key).await {
                discovered.extend(results);
            }
        }

        // 2. Bugcrowd
        if let Some(key) = &self.bugcrowd_api_key {
            if let Ok(results) = self.run_bbscope("bc", None, key).await {
                discovered.extend(results);
            }
        }

        // 3. Intigriti
        if let Some(token) = &self.intigriti_token {
            if let Ok(results) = self.run_bbscope("it", None, token).await {
                discovered.extend(results);
            }
        }

        Ok(discovered)
    }
}

impl BBScopeScanner {
    async fn run_bbscope(&self, platform: &str, user: Option<&str>, token: &str) -> Result<Vec<DiscoveryResult>> {
        let mut cmd = tokio::process::Command::new(&self.binary_path);
        cmd.arg(platform)
           .arg("-t").arg(token);
        
        if let Some(u) = user {
            cmd.arg("-u").arg(u);
        }

        // We want only in-scope items and typically we want hostnames/wildcards
        cmd.arg("-o").arg("t"); // Output type: targets

        let output = cmd.stdout(Stdio::piped())
                        .stderr(Stdio::null())
                        .spawn()?
                        .wait_with_output()
                        .await?;

        if !output.status.success() {
            warn!("bbscope {} failed", platform);
            return Ok(Vec::new());
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut results = Vec::new();
        for line in stdout.lines() {
            let target = line.trim().to_string();
            if !target.is_empty() && !target.contains('*') { // Simplistic wildcard handling
                 results.push(DiscoveryResult {
                     host: target,
                     metadata: serde_json::json!({ "platform": platform }),
                 });
            } else if target.contains("*.") {
                 results.push(DiscoveryResult {
                     host: target.replace("*.", ""),
                     metadata: serde_json::json!({ "platform": platform }),
                 });
            }
        }

        Ok(results)
    }
}
