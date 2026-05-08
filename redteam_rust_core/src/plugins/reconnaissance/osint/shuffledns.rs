use crate::plugins::{DiscoveryPlugin, Capability, PluginMetadata, RiskLevel, TargetType, DiscoveryResult};
use crate::models::TargetHost;
use crate::utils::tool_detection::detect_tool_system;
use crate::core::capability_layer::ScanLayer;
use crate::models::constants::PLUGIN_SHUFFLEDNS;
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::{info, warn};
use std::process::Stdio;
use std::time::Duration;
use tokio::time::timeout;

pub struct ShufflednsScanner {
    binary_path: Option<String>,
    massdns_path: Option<String>,
    resolvers_path: Option<String>,
    wordlist_path: Option<String>,
}

impl ShufflednsScanner {
    pub fn new<M: crate::utils::executor::ExecutorMode>(config: &crate::plugins::GlobalConfig<M>) -> Self {
        // Resolver binary_path
        let binary_path = config.shuffledns_path.clone().or_else(|| {
            match detect_tool_system("shuffledns") {
                Ok(Some(path)) => Some(path.to_string_lossy().into_owned()),
                _ => None,
            }
        });

        // Resolver massdns_path
        let massdns_path = config.massdns_path.clone().or_else(|| {
            match detect_tool_system("massdns") {
                Ok(Some(path)) => Some(path.to_string_lossy().into_owned()),
                _ => None,
            }
        });

        Self {
            binary_path,
            massdns_path,
            resolvers_path: config.shuffledns_resolvers_path.clone(),
            wordlist_path: config.shuffledns_wordlist_path.clone(),
        }
    }
}

#[async_trait]
impl DiscoveryPlugin for ShufflednsScanner {
    fn name(&self) -> &'static str {
        PLUGIN_SHUFFLEDNS
    }

    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: self.name().to_string(),
            description: "ShuffleDNS: MassDNS wrapper for bruteforcing and wildcard resolution.".to_string(),
            target_type: TargetType::Osint,
            risk_level: RiskLevel::Safe, // Active bruteforcing, but safe against target integrity
            layer: ScanLayer::Passive, // Grouped in recon layer
            category: "Reconnaissance".to_string(),
            expected_duration: Duration::from_secs(660), // Increased to 660s to avoid collision with the 600s hard timeout
            capabilities: self.capabilities(),
            cost: 8,
            mitre_attacks: vec!["T1589.001".to_string()],
            exploit_difficulty: RiskLevel::Medium,
            ..Default::default()
        }
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::SubdomainEnumeration]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        let mut all_ok = true;

        if let Some(path) = &self.binary_path {
            if !tokio::fs::try_exists(path).await.unwrap_or(false) {
                warn!("ShuffleDNS binary not found at specified path: {}", path);
                all_ok = false;
            }
        } else {
            warn!("ShuffleDNS binary path is not configured and not found in PATH.");
            all_ok = false;
        }

        if let Some(path) = &self.massdns_path {
            if !tokio::fs::try_exists(path).await.unwrap_or(false) {
                warn!("MassDNS binary not found at specified path: {}", path);
                all_ok = false;
            }
        } else {
            warn!("MassDNS binary path is not configured and not found in PATH.");
            all_ok = false;
        }

        if let Some(path) = &self.resolvers_path {
            if !tokio::fs::try_exists(path).await.unwrap_or(false) {
                warn!("ShuffleDNS resolvers list not found at: {}", path);
                all_ok = false;
            }
        } else {
            warn!("ShuffleDNS resolvers path is not configured.");
            all_ok = false;
        }

        if let Some(path) = &self.wordlist_path {
            if !tokio::fs::try_exists(path).await.unwrap_or(false) {
                warn!("ShuffleDNS wordlist not found at: {}", path);
                all_ok = false;
            }
        } else {
            warn!("ShuffleDNS wordlist path is not configured.");
            all_ok = false;
        }

        Ok(all_ok)
    }

    async fn discover(&self, target: &TargetHost) -> Result<Vec<DiscoveryResult>> {
        info!("ShufflednsScanner: initiating subdomain bruteforce for {}", target.host);

        // Safe extraction avoiding unwrap() panic risks
        let bin_path = self.binary_path.as_ref()
            .context("ShufflednsScanner invariant violated: binary_path is None during discover")?;
        let massdns_bin = self.massdns_path.as_ref()
            .context("ShufflednsScanner invariant violated: massdns_path is None during discover")?;
        let wordlist = self.wordlist_path.as_ref()
            .context("ShufflednsScanner invariant violated: wordlist_path is None during discover")?;
        let resolvers = self.resolvers_path.as_ref()
            .context("ShufflednsScanner invariant violated: resolvers_path is None during discover")?;

        let temp_output = tempfile::NamedTempFile::new().context("Failed to create temp output for ShuffleDNS")?;
        let output_path = temp_output.path().to_string_lossy().to_string();

        let mut cmd = tokio::process::Command::new(bin_path);
        cmd.arg("-d").arg(&target.host)
            .arg("-w").arg(wordlist)
            .arg("-r").arg(resolvers)
            .arg("-massdns").arg(massdns_bin)
            .arg("-mode").arg("bruteforce")
            .arg("-t").arg("100") // OPSEC Safe Concurrency
            .arg("-silent")
            .arg("-o").arg(&output_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped()); // Piped stderr to capture critical binary errors even with -silent

        let mut child = cmd.spawn().context("Failed to spawn shuffledns")?;

        // Wrapping with 10 min timeout
        match timeout(Duration::from_secs(600), child.wait()).await {
            Ok(Ok(status)) => {
                if !status.success() {
                    warn!("ShuffleDNS execution failed for {}", target.host);
                }
            }
            Ok(Err(e)) => {
                warn!("ShuffleDNS process error for {}: {}", target.host, e);
            }
            Err(_) => {
                warn!("ShuffleDNS execution timed out (600s) for {}", target.host);
                let _ = child.kill().await;
            }
        }

        let mut discovered = Vec::new();
        if let Ok(file) = tokio::fs::File::open(&output_path).await {
            use tokio::io::{AsyncBufReadExt, BufReader};
            let mut lines = BufReader::new(file).lines();
            while let Some(line) = lines.next_line().await? {
                let domain = line.trim().to_string();
                if !domain.is_empty() {
                    discovered.push(DiscoveryResult { host: domain, metadata: serde_json::json!({"source": "shuffledns_bruteforce"}) });
                }
            }
        }

        info!("ShufflednsScanner: found {} verified subdomains for {}", discovered.len(), target.host);
        Ok(discovered)
    }
}
