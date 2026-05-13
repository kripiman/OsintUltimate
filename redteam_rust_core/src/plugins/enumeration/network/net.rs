use crate::plugins::{ScannerPlugin, Capability};
use crate::models::{TargetHost, Finding};
use crate::utils::executor::{StealthExecutor, ExecutorMode};

pub struct NmapScanner<M: ExecutorMode> {
    scripts: Option<String>,
    stealth: bool,
    service_detection: bool,
    scan_type: String,
    fragment: bool,
    decoy: Option<String>,
    ports: Option<String>,
    vuln_scan: bool,
    executor: Arc<StealthExecutor<M>>,
}

impl<M: ExecutorMode> NmapScanner<M> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scripts: Option<String>, 
        stealth: bool, 
        service_detection: bool,
        scan_type: String,
        fragment: bool,
        decoy: Option<String>,
        ports: Option<String>,
        vuln_scan: bool,
        executor: Arc<StealthExecutor<M>>,
    ) -> Self {
        Self {
            scripts,
            stealth,
            service_detection,
            scan_type,
            fragment,
            decoy,
            ports,
            vuln_scan,
            executor,
        }
    }
}

use crate::plugins::enumeration::network::nmap::parse_nmap_xml;
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::{info, warn, error};
use std::sync::Arc;
use once_cell::sync::Lazy;

// V14.1 HARDENING: Domain-specific regexes for argument validation (Consulted before spawn)
static TARGET_HOST_RE: Lazy<regex::Regex> = Lazy::new(|| regex::Regex::new(r"^[a-zA-Z0-9.\-:]+$").unwrap());
static DECOY_RE: Lazy<regex::Regex> = Lazy::new(|| regex::Regex::new(r"^[a-zA-Z0-9.,_]+$").unwrap());
static SCRIPT_RE: Lazy<regex::Regex> = Lazy::new(|| regex::Regex::new(r"^[a-zA-Z0-9,-]+$").unwrap());

#[async_trait]
impl<M: ExecutorMode> ScannerPlugin for NmapScanner<M> {
    fn name(&self) -> &'static str {
        crate::models::PLUGIN_NMAP
    }

    fn metadata(&self) -> crate::plugins::PluginMetadata {
        crate::plugins::PluginMetadata {
            name: self.name().to_string(),
            description: "Port scanning, service detection, and OS fingerprinting using Nmap. Essential for initial network discovery.".to_string(),
            target_type: crate::plugins::TargetType::Network,
            risk_level: crate::plugins::RiskLevel::Medium,
            layer: crate::core::capability_layer::ScanLayer::Scanning,
            expected_duration: std::time::Duration::from_secs(300),
            capabilities: self.capabilities(),
            cost: 5,
            category: "Enumeration".to_string(),
            mitre_attacks: vec!["T1046".to_string()],
            exploit_difficulty: crate::plugins::RiskLevel::Low,
            blackarch_category: Some("scanner".to_string()),
            is_destructive: false,
            poc_mode: true, ..Default::default() }
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::VulnerabilityScanning]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability("nmap").await)
    }

    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        let target_addr = target.pinned_addr()?;
        info!("NmapScanner: launching scan against {} (via {})", target.host, target_addr);
        
        if !TARGET_HOST_RE.is_match(&target.host) || target.host.starts_with('-') {
            warn!("NmapScanner: Skipping invalid/unsafe target: {}", target.host);
            return Ok(Vec::new());
        }

        let mut args = vec!["-n".to_string(), "-Pn".to_string(), "--open".to_string(), "-oX".to_string(), "-".to_string()];

        // 1. Port selection
        if let Some(ports) = &self.ports {
            args.push("-p".to_string());
            args.push(ports.clone());
        } else {
            let port_count = if self.vuln_scan { "5000" } else { "3000" };
            args.push("--top-ports".to_string());
            args.push(port_count.to_string());
        }

        // 2. Timing and Retries
        let (speed, timeout) = if self.stealth { ("-T2", "12h") } else { ("-T4", if self.vuln_scan { "24h" } else { "4h" }) };
        args.push(speed.to_string());
        args.push("--host-timeout".to_string());
        args.push(timeout.to_string());
        args.push("--max-retries".to_string());
        args.push("3".to_string());

        // 3. Scan Type & Stealth features
        args.push(format!("-{}", self.scan_type));
        if self.fragment { args.push("-f".to_string()); }
        if let Some(decoy) = &self.decoy {
            if DECOY_RE.is_match(decoy) && !decoy.starts_with('-') { args.push(format!("-D{}", decoy)); }
        }

        // 4. Vulnerability & Scripts
        if self.vuln_scan {
            args.push("-sV".to_string());
            args.push("--version-intensity".to_string()); args.push("9".to_string());
            args.push("-O".to_string());
            args.push("--osscan-guess".to_string());
            args.push("--script=vuln,exploit,auth,default,discovery".to_string());
            args.push("--script-timeout".to_string()); args.push("10m".to_string());
        } else {
            if self.service_detection { args.push("-sV".to_string()); }
            if let Some(scripts) = &self.scripts {
                if SCRIPT_RE.is_match(scripts) { args.push(format!("--script={}", scripts)); }
            }
        }

        args.push(target_addr.to_string());

        // V14.1 SOVEREIGN EXECUTION: Delegate to unified StealthExecutor
        let output = self.executor.execute_and_wait("nmap", args).await
            .context("Fallo en la ejecución de Nmap a través del StealthExecutor")?;

        if !output.status.success() {
             error!("Nmap failed on {} with status: {}", target.host, output.status);
             return Ok(Vec::new());
        }

        // V14.1 DOMAIN PARSING: Delegate to isolated domain parser
        let findings = parse_nmap_xml(&output.stdout[..])?;
        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_nmap_target_validation() {
        assert!(TARGET_HOST_RE.is_match("google.com"));
        assert!(!TARGET_HOST_RE.is_match("google.com; rm -rf /"));
    }
}
