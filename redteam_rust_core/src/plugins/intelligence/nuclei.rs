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
    tags: Option<String>,
    severity: Option<String>,
    custom_templates: Option<String>,
    auto_update: bool,
}

impl<M: ExecutorMode> NucleiScanner<M> where M: Clone {
    pub fn new(config: crate::plugins::GlobalConfig<M>) -> Self {
        let path = detect_tool("nuclei");
        Self {
            binary_path: path,
            executor: config.executor,
            tags: config.nuclei_tags,
            severity: config.nuclei_severity,
            custom_templates: config.nuclei_custom_templates,
            auto_update: config.nuclei_auto_update,
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
            exploit_difficulty: crate::plugins::RiskLevel::Medium,
            blackarch_category: Some("scanner".to_string()),
            is_destructive: false,
            poc_mode: true, ..Default::default() }
    }
    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::VulnerabilityScanning]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        let available = crate::utils::check_tool_availability("nuclei").await;
        if available {
            // V14.2: Auto-update templates if enabled
            // We use a simple atomic or check a global state to avoid multiple updates in the same run
            static UPDATED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
            
            // Check if auto-update is enabled in the config (passed via GlobalConfig if we add it there)
            // For now, we'll check a flag if we can access it, or just use a placeholder.
            // Since check_dependencies doesn't have access to the full config easily without modifying the trait,
            // we'll assume it's controlled by an environment variable for now or we update the struct.
            if self.auto_update && !UPDATED.swap(true, std::sync::atomic::Ordering::SeqCst) {
                info!("🔄 NUCLEI: Updating templates...");
                let _ = self.executor.execute_and_wait(&self.binary_path, vec!["-update-templates".to_string()]).await;
            }
        }
        Ok(available)
    }


    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        // V14.2 SCOPE CHECK
        // Assuming we have access to a policy provider here or via the target
        // For now, we'll keep the DNS pinning but we've improved the underlying policy system.
        
        // V13 HARDENING: Mandatory DNS Pinning (ResolvedIP) for all network-bound plugins.
        let pinned_ip = target.pinned_addr()
            .context("DNS Pinning Violation: Nuclei requires a resolved and pinned IP to prevent Rebinding.")?;
        
        info!("NucleiScanner: launching hardened scan against {} (Pinned: {})", target.host, pinned_ip);

        let url = format!("http://{}", pinned_ip);
        
        // V13 HARDENING: Set Host header to the original hostname to support vhosts on pinned IP.
        let host_header = format!("Host: {}", target.host);

        let temp_file = tempfile::NamedTempFile::new().context("Failed to create temp file for Nuclei")?;
        let temp_path = temp_file.path().to_string_lossy().to_string();

        let mut args = vec![
            "-u".to_string(), url.clone(),
            "-H".to_string(), host_header.clone(),
            "-jsonl".to_string(),
            "-o".to_string(), temp_path.clone(),
            "-silent".to_string(),
        ];

        // V14.2 NUCLEI EXPANSION: Inject custom filters and templates
        if let Some(ref t) = self.tags {
            args.push("-tags".to_string());
            args.push(t.clone());
        }

        if let Some(ref s) = self.severity {
            args.push("-severity".to_string());
            args.push(s.clone());
        }

        if let Some(ref ct) = self.custom_templates {
            args.push("-t".to_string());
            args.push(ct.clone());
        }

        // V14.2: Use optimized config if available — resolve relative to binary, then CWD.
        let config_path = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join("nuclei-config.yaml")))
            .filter(|p| p.exists())
            .unwrap_or_else(|| std::path::PathBuf::from("nuclei-config.yaml"));

        if config_path.exists() {
            args.push("-config".to_string());
            args.push(config_path.to_string_lossy().to_string());
        }

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

                    // V14.2 TRIAGE: Inline filter to exclude low-value findings
                    if matches!(severity, Severity::Info | Severity::Low) {
                        continue;
                    }

                    let finding = Finding::new(
                        &format!("NUCLEI-{}", res.template_id.to_uppercase()),
                        Category::Vulnerability,
                        severity,
                        &format!("{}: {}", res.info.name, res.info.description.unwrap_or_default()),
                        serde_json::json!({
                            "template_id": res.template_id,
                            "matched_at": res.matched_at,
                        })
                    );

                    // V14.2 DEDUPLICATION: Check if we've seen this exact finding before
                    if crate::utils::deduplication::DeduplicationEngine::is_duplicate(&finding) {
                        info!("♻️ V14.2 DEDUPE: Skipping duplicate Nuclei finding: {}", finding.id);
                        continue;
                    }

                    findings.push(finding);
                }
            }
        }

        Ok(findings)
    }
}
