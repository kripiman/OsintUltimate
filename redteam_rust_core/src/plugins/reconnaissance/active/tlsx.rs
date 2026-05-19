use crate::plugins::{ScannerPlugin, Capability, PluginMetadata, RiskLevel, TargetType};
use crate::models::{TargetHost, Finding, Category, Severity};
use crate::utils::tool_detection::detect_tool;
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::info;
use std::process::Stdio;
use tokio::sync::mpsc::Sender;
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct TlsxScanner {
    binary_path: String,
    feedback_tx: Arc<RwLock<Option<Sender<TargetHost>>>>,
}

impl Default for TlsxScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl TlsxScanner {
    pub fn new() -> Self {
        let path = detect_tool("tlsx");
        Self {
            binary_path: path,
            feedback_tx: Arc::new(RwLock::new(None)),
        }
    }
}

#[async_trait]
impl ScannerPlugin for TlsxScanner {
    fn name(&self) -> &'static str {
        crate::models::PLUGIN_TLSX
    }

    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: self.name().to_string(),
            description: "tlsx: TLS discovery and fingerprinting tool.".to_string(),
            target_type: TargetType::Host,
            risk_level: RiskLevel::Safe,
            layer: crate::core::capability_layer::ScanLayer::Scanning,
            expected_duration: std::time::Duration::from_secs(30),
            capabilities: vec![Capability::TlsFingerprinting],
            cost: 2,
            category: "Reconnaissance".to_string(),
            ..Default::default()
        }
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::TlsFingerprinting]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability("tlsx").await)
    }

    fn set_feedback_channel(&self, tx: Sender<TargetHost>) {
        let feedback_tx = self.feedback_tx.clone();
        tokio::spawn(async move {
            let mut lock = feedback_tx.write().await;
            *lock = Some(tx);
        });
    }

    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        let addr = target.ip.as_deref().unwrap_or(&target.host);
        info!("TlsxScanner: launching scan for {}", addr);

        let child = tokio::process::Command::new(&self.binary_path)
            .arg("-u").arg(addr)
            .arg("-san")
            .arg("-cn")
            .arg("-silent")
            .arg("-json")
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .context("Failed to spawn tlsx")?;

        let output = child.wait_with_output().await?;
        if !output.status.success() {
            return Ok(Vec::new());
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut findings = Vec::new();
        
        let feedback_tx_lock = self.feedback_tx.read().await;

        for line in stdout.lines() {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(line) {
                // Extract SANs
                if let Some(sans) = json.get("san").and_then(|v| v.as_array()) {
                    for san in sans {
                        if let Some(host) = san.as_str() {
                            findings.push(
                                Finding::builder(
                                    &format!("DISCOVERED_SUBDOMAIN_TLSX_{}", host),
                                    Category::Recon,
                                    Severity::Info,
                                    &format!("New asset discovered via TLS SAN pivot: {}", host)
                                ).build()
                            );
                            
                            // Feedback Loop: Inject new target
                            if let Some(tx) = &*feedback_tx_lock {
                                let new_target = TargetHost {
                                    host: host.to_string(),
                                    ip: None,
                                    resolved_ip: None,
                                    status: crate::models::TargetStatus::Pending,
                                    target_type: TargetType::Host,
                                    file_path: None,
                                    user: None,
                                    findings: Arc::new(Vec::new()),
                                    tool_suggestions: Arc::new(Vec::new()),
                                    tactical_context: Arc::new(serde_json::json!({})),
                                    extra_data: Arc::new(serde_json::json!({})),
                                    version: 0,
                                    skip_heavy_scan: false,
                                    scan_id: None,
                                    scope_id: String::new(),
                                };
                                
                                // ARCH-11 Fix: Avoid blocking orchestrator/reactive loop deadlocks
                                // We use a timeout to prevent infinite blocking if the channel is full.
                                let tx_clone = tx.clone();
                                let host_clone = host.to_string();
                                tokio::spawn(async move {
                                    match tokio::time::timeout(std::time::Duration::from_secs(5), tx_clone.send(new_target)).await {
                                        Ok(Ok(_)) => {},
                                        Ok(Err(_)) => {
                                            // Send error (channel closed)
                                        },
                                        Err(_) => {
                                            tracing::warn!("⚠️ FEEDBACK DEADLOCK AVOIDED: Dropping recon target {} due to 5s timeout.", host_clone);
                                        }
                                    }
                                });
                            }
                        }
                    }
                }
            }
        }

        Ok(findings)
    }
}
