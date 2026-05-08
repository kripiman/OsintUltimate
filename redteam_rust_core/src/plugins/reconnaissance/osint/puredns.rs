use crate::plugins::{DiscoveryPlugin, Capability, PluginMetadata, RiskLevel, TargetType, DiscoveryResult};
use crate::models::TargetHost;
use crate::utils::tool_detection::detect_tool;
use crate::utils::proxy::ProxyManager;
use crate::core::capability_layer::ScanLayer;
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::{info, warn};
use std::sync::Arc;
use std::process::Stdio;

pub struct PurednsScanner {
    binary_path: String,
    proxy_manager: Arc<ProxyManager>,
}

impl PurednsScanner {
    pub fn new(pm: Arc<ProxyManager>) -> Self {
        let path = detect_tool("puredns");
        Self {
            binary_path: path,
            proxy_manager: pm,
        }
    }
}

#[async_trait]
impl DiscoveryPlugin for PurednsScanner {
    fn name(&self) -> &'static str {
        "puredns"
    }

    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: self.name().to_string(),
            description: "Puredns: Mass DNS resolver and wildcard filter for high-quality subdomain enumeration.".to_string(),
            target_type: TargetType::Osint,
            risk_level: RiskLevel::Safe,
            layer: ScanLayer::Passive,
            category: "Reconnaissance".to_string(),
            expected_duration: std::time::Duration::from_secs(300),
            capabilities: self.capabilities(),
            cost: 4,
            mitre_attacks: vec!["T1589.001".to_string()],
            exploit_difficulty: RiskLevel::Medium,
            ..Default::default()
        }
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::SubdomainEnumeration]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability("puredns").await)
    }

    async fn discover(&self, target: &TargetHost) -> Result<Vec<DiscoveryResult>> {
        info!("PurednsScanner: performing wildcard-filtered resolution for {}", target.host);

        // 1. Prepare resolvers (Fail-safe default or from env)
        let resolvers_path = std::env::var("PUREDNS_RESOLVERS").unwrap_or_else(|_| "/usr/share/puredns/resolvers.txt".to_string());
        
        // 2. We need a list of subdomains to resolve. 
        // If this is a standalone discovery plugin, we might want to run a small brute force 
        // or resolve subdomains leant from other plugins if we had access to them.
        // For now, we'll perform a high-speed resolution of the target domain + common prefixes
        // as a baseline 'puredns' utility.
        
        let temp_input = tempfile::NamedTempFile::new().context("Failed to create temp input for Puredns")?;
        let temp_output = tempfile::NamedTempFile::new().context("Failed to create temp output for Puredns")?;
        
        let input_path = temp_input.path().to_string_lossy().to_string();
        let output_path = temp_output.path().to_string_lossy().to_string();

        // Write some common subdomains to the input file for a basic 'discovery' check
        // In a real scenario, this would be fed by a massive wordlist or passive data
        {
            use std::io::Write;
            let mut file = std::fs::File::create(&input_path)?;
            for sub in &["www", "dev", "api", "staging", "test", "vpn", "mail", "admin", "portal", "corp", "internal"] {
                writeln!(file, "{}.{}", sub, target.host)?;
            }
        }

        let mut cmd = crate::utils::common::stealth_command(&self.binary_path, Some(&self.proxy_manager));
        cmd.arg("resolve")
            .arg(&input_path)
            .arg("-r").arg(&resolvers_path)
            .arg("--write").arg(&output_path)
            .arg("--bin").arg(detect_tool("dnsx")) // Use dnsx for speed if available
            .arg("-p").arg("50") // concurrency
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        let mut child = cmd.spawn().context("Failed to spawn puredns")?;
        let status = child.wait().await.context("Failed to wait for puredns")?;

        if !status.success() {
            warn!("Puredns resolve failed for {}", target.host);
        }

        let mut discovered = Vec::new();
        if let Ok(file) = tokio::fs::File::open(&output_path).await {
            use tokio::io::{AsyncBufReadExt, BufReader};
            let mut lines = BufReader::new(file).lines();
            while let Some(line) = lines.next_line().await? {
                let domain = line.trim().to_string();
                if !domain.is_empty() {
                    discovered.push(DiscoveryResult { host: domain, metadata: serde_json::json!({}) });
                }
            }
        }

        info!("PurednsScanner: found {} verified subdomains for {}", discovered.len(), target.host);
        Ok(discovered)
    }
}
