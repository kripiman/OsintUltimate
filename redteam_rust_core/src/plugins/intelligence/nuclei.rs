use crate::plugins::{ScannerPlugin, Capability};
use crate::models::{TargetHost, Finding, Severity, Category};
use crate::utils::tool_detection::detect_tool;
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::{info, warn};
use serde::Deserialize;
use crate::utils::executor::{StealthExecutor, ExecutorMode};

#[derive(Debug, Deserialize)]
struct NucleiResult {
    #[serde(rename = "template-id")]
    template_id: String,
    info: NucleiInfo,
    #[serde(rename = "matched-at")]
    matched_at: String,
}

#[derive(Debug, Deserialize)]
struct NucleiInfo {
    name: String,
    severity: String,
    description: Option<String>,
}

pub struct NucleiScanner<M: ExecutorMode> {
    binary_path: String,
    executor: std::sync::Arc<StealthExecutor<M>>,
}

impl<M: ExecutorMode> NucleiScanner<M> {
    pub fn new(executor: std::sync::Arc<StealthExecutor<M>>) -> Self {
        let path = detect_tool("nuclei");
        Self {
            binary_path: path,
            executor,
        }
    }
}

#[async_trait]
impl<M: ExecutorMode> ScannerPlugin for NucleiScanner<M> {
    fn name(&self) -> &'static str {
        crate::models::PLUGIN_NUCLEI
    }

        fn metadata(&self) -> crate::plugins::PluginMetadata {
        crate::plugins::PluginMetadata {
            name: self.name().to_string(),
            description: "Template-based vulnerability scanning using Nuclei. Highly effective for detecting misconfigurations and known CVEs.".to_string(),
            target_type: crate::plugins::TargetType::Host,
            risk_level: crate::plugins::RiskLevel::Medium,
            layer: crate::core::capability_layer::ScanLayer::Scanning,
            expected_duration: std::time::Duration::from_secs(300),
            capabilities: self.capabilities(),
            cost: 5,
            category: "Intelligence".to_string(),
            mitre_attacks: vec!["T1595".to_string(), "T1190".to_string()],
            remediation_difficulty: crate::plugins::RiskLevel::Medium,
            blackarch_category: Some("scanner".to_string()),
            is_destructive: false,
            poc_mode: true,
        }
    }
    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::VulnerabilityScanning]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability("nuclei").await)
    }


    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        // V13 HARDENING: Mandatory DNS Pinning (ResolvedIP) for all network-bound plugins.
        let pinned_ip = target.pinned_addr()
            .context("DNS Pinning Violation: Nuclei requires a resolved and pinned IP to prevent Rebinding.")?;
        
        info!("NucleiScanner: launching hardened scan against {} (Pinned: {})", target.host, pinned_ip);

        let url = format!("http://{}", pinned_ip);
        
        // V13 HARDENING: Set Host header to the original hostname to support vhosts on pinned IP.
        let host_header = format!("Host: {}", target.host);

        let temp_file = tempfile::NamedTempFile::new().context("Failed to create temp file for Nuclei")?;
        let temp_path = temp_file.path().to_string_lossy().to_string();

        let args = vec![
            "-u".to_string(), url.clone(),
            "-H".to_string(), host_header.clone(),
            "-jsonl".to_string(),
            "-o".to_string(), temp_path.clone(),
            "-silent".to_string(),
        ];

        let output = self.executor.execute_and_wait(&self.binary_path, args).await
            .context("Failed to spawn nuclei")?;

        let status = output.status;

        if !status.success() {
            warn!("Nuclei failed on {}", target.host);
            // Nuclei might return 1 if no vulns found in some versions, but usually 0.
            // We proceed to check the file anyway.
        }

        let mut findings = Vec::new();

        if let Ok(content) = tokio::fs::read_to_string(&temp_path).await {
            for line in content.lines() {
                if let Ok(res) = serde_json::from_str::<NucleiResult>(line) {
                    let severity = match res.info.severity.as_str() {
                        "critical" => Severity::Critical,
                        "high" => Severity::High,
                        "medium" => Severity::Medium,
                        "low" => Severity::Low,
                        _ => Severity::Info,
                    };

                    findings.push(Finding::new(
                        &format!("NUCLEI-{}", res.template_id.to_uppercase()),
                        Category::Vulnerability,
                        severity,
                        &format!("{}: {}", res.info.name, res.info.description.unwrap_or_default()),
                        serde_json::json!({
                            "template_id": res.template_id,
                            "matched_at": res.matched_at,
                        })
                    ));
                }
            }
        }

        Ok(findings)
    }
}
