use crate::plugins::{ScannerPlugin, Capability, PluginMetadata, RiskLevel, TargetType};
use crate::models::{TargetHost, Finding, Severity, Category};
use crate::core::capability_layer::ScanLayer;
use crate::core::net_evasion::cache_deception::{CacheDeceptionProbe, CacheDeceptionConfig};
use crate::core::net_evasion::http_smuggle::Confidence;
use async_trait::async_trait;
use anyhow::Result;
use tracing::{info, warn};
use url::Url;
use crate::models::constants::*;

pub struct WcdScanner {}

impl Default for WcdScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl WcdScanner {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl ScannerPlugin for WcdScanner {
    fn name(&self) -> &'static str {
        PLUGIN_WCD
    }

    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: self.name().to_string(),
            description: "Scanner for Web Cache Deception vulnerabilities. Identifies sensitive data leakage via cache-poisoned static extensions.".to_string(),
            target_type: TargetType::Web,
            risk_level: RiskLevel::Low,
            layer: ScanLayer::Scanning,
            category: "Web".to_string(),
            expected_duration: std::time::Duration::from_secs(60),
            capabilities: vec![Capability::VulnerabilityScanning],
            cost: 2,
            mitre_attacks: vec!["T1595.002".to_string()],
            exploit_difficulty: RiskLevel::Medium,
            blackarch_category: Some("webapp".to_string()),
            is_destructive: false,
            poc_mode: true, ..Default::default() }
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::VulnerabilityScanning]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        // Native Rust implementation using reqwest. No external binary needed.
        Ok(true)
    }

    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        info!("WcdScanner: scanning {}", target.host);
        
        let mut findings = Vec::new();
        let base_url_str = if target.host.starts_with("http") {
            target.host.clone()
        } else if target.host.ends_with(":443") || target.host.ends_with(":8443") {
            format!("https://{}", target.host)
        } else {
            format!("http://{}", target.host)
        };

        let parsed_url = match Url::parse(&base_url_str) {
            Ok(u) => u,
            Err(e) => {
                warn!("WcdScanner: invalid URL {}: {}", base_url_str, e);
                return Ok(findings);
            }
        };

        let scheme = parsed_url.scheme();
        let host = parsed_url.host_str().unwrap_or(&target.host);
        let port = parsed_url.port().unwrap_or_else(|| if scheme == "http" { 80 } else { 443 });

        // 1. Identify sensitive paths to probe
        let mut paths_to_probe = vec![
            "/".to_string(),
            "/home".to_string(),
            "/dashboard".to_string(),
            "/api/v1/user".to_string(),
            "/profile".to_string(),
            "/settings".to_string(),
            "/account".to_string(),
        ];

        let mut sensitive_markers = Vec::new();

        for f in target.findings.iter() {
             if let Some(ev) = &f.evidence.primary {
                 if let Some(path) = ev.data.get("path").and_then(|v| v.as_str()) {
                     if !path.contains(".") && path.len() > 1 { paths_to_probe.push(path.to_string()); }
                 }
                 // Extract dynamic markers from evidence (e.g. emails, usernames, UUIDs)
                 if let Some(email) = ev.data.get("email").and_then(|v| v.as_str()) {
                     sensitive_markers.push(email.to_string());
                 }
                 if let Some(uuid) = ev.data.get("uuid").and_then(|v| v.as_str()) {
                     sensitive_markers.push(uuid.to_string());
                 }
                 if let Some(token) = ev.data.get("token").and_then(|v| v.as_str()) {
                     sensitive_markers.push(token.to_string());
                 }
             }
        }
        paths_to_probe.sort();
        paths_to_probe.dedup();

        // If no dynamic markers found, we will just proceed with empty markers.
        // It's better to not flag than to false-positive on generic words.

        // Configure the probe
        let config = CacheDeceptionConfig {
            session_cookie: target.tactical_context.get("session_cookie").and_then(|v| v.as_str()).map(|s| s.to_string()),
            sensitive_markers,
        };

        // 2. Perform probing with static extensions
        let extensions = [".css", ".jpg", ".js", ".v14"];
        
        for path in paths_to_probe.into_iter().take(15) {
            let normalized_path = if path.starts_with('/') { path } else { format!("/{}", path) };
            
            // We do a single extension probe per path to avoid spamming
            // In a real scenario we'd test all extensions, but we'll stick to a subset or loop.
            for ext in &extensions {
                // Call the native cache deception probe
                let result = CacheDeceptionProbe::probe(
                    host,
                    port,
                    scheme,
                    &format!("{}{}", normalized_path, ext),
                    &config
                ).await;

                match result {
                    Ok(probe_res) => {
                        if probe_res.vulnerable && probe_res.confidence == Confidence::Definite {
                            let probe_url = format!("{}://{}:{}{}{}", scheme, host, port, normalized_path, ext);
                            findings.push(Finding::new(
                                FINDING_WEB_CACHE_DECEPTION,
                                Category::Vulnerability,
                                Severity::High, // Elevated to High due to cross-user definite leak
                                &format!("Cross-user Web Cache Deception proven at {}", probe_url),
                                serde_json::json!({
                                    "url": probe_url,
                                    "response_time_ms": probe_res.response_time_ms,
                                    "cache_headers": probe_res.cache_headers,
                                    "markers_leaked": config.sensitive_markers,
                                })
                            ).with_tactical_path("Unauthenticated attacker successfully retrieved authenticated cached sensitive data. Mitigate by enforcing Cache-Control: no-store on sensitive endpoints and validating extensions on the backend."));
                            break; // Move to next path
                        }
                    }
                    Err(e) => {
                        warn!("WcdScanner: probe error for {}{}: {}", normalized_path, ext, e);
                    }
                }
            }
        }

        Ok(findings)
    }
}
