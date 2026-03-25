use crate::plugins::{ScannerPlugin, Capability};
use crate::models::{TargetHost, Finding, Severity, Category};
use crate::utils::tool_detection::detect_tool;
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::{info, error, warn};
use std::process::Stdio;
use tokio::process::Command;
use once_cell::sync::Lazy;

use serde::Deserialize;

// QA-010 FIX: Module-scope Lazy Regexes — compiled once per process, not per-thread.
static TARGET_HOST_RE: Lazy<regex::Regex> = Lazy::new(|| regex::Regex::new(r"^[a-zA-Z0-9.\-:]+$").unwrap());
static DECOY_RE: Lazy<regex::Regex> = Lazy::new(|| regex::Regex::new(r"^[a-zA-Z0-9.,_]+$").unwrap());
static SCRIPT_RE: Lazy<regex::Regex> = Lazy::new(|| regex::Regex::new(r"^[a-zA-Z0-9,-]+$").unwrap());

pub struct NmapScanner {
    nmap_path: String,
    scripts: Option<String>,
    stealth: bool,
    service_detection: bool,
    scan_type: String,
    fragment: bool,
    decoy: Option<String>,
    ports: Option<String>,
    vuln_scan: bool,
}

// Known critical vulnerability patterns for severity classification
static CRITICAL_PATTERNS: Lazy<Vec<&str>> = Lazy::new(|| vec!["ms17-010", "eternalblue", "heartbleed", "shellshock", "bluekeep", "ms08-067", "ms12-020", "cve-2017", "cve-2018", "cve-2019", "cve-2020", "cve-2021", "cve-2022", "cve-2023", "cve-2024", "cve-2025", "cve-2026", "rce", "remote-code-execution", "command-injection", "smb-vuln-ms17", "smb-vuln-cve", "http-vuln-cve", ]);

static CRITICAL_OUTPUT_PATTERNS: Lazy<Vec<&str>> = Lazy::new(|| vec!["state: vulnerable", "exploitable", "remote code execution", "allows remote attackers", "unauthenticated", ]);

static MEDIUM_PATTERNS: Lazy<Vec<&str>> = Lazy::new(|| vec!["auth", "brute", "default-credentials", "default-password", "weak-password", "anonymous", "enum", "info-disclosure", ]);

// Structs for QuickXML parsing
#[derive(Debug, Deserialize)]
struct NmapRun {
    host: Option<Vec<Host>>,
}

#[derive(Debug, Deserialize)]
struct Host {
    ports: Option<Ports>,
    os: Option<Os>,
}

#[derive(Debug, Deserialize)]
struct Os {
    osmatch: Option<Vec<OsMatch>>,
}

#[derive(Debug, Deserialize)]
struct OsMatch {
    #[serde(rename = "@name", default)]
    name: String,
    #[serde(rename = "@accuracy", default)]
    accuracy: String,
}

#[derive(Debug, Deserialize)]
struct Ports {
    port: Option<Vec<Port>>,
}

#[derive(Debug, Deserialize)]
struct Port {
    #[serde(rename = "@portid")]
    portid: u16,
    #[serde(rename = "@protocol")]
    protocol: String,
    service: Option<Service>,
    script: Option<Vec<Script>>, // Support for script output per port
}

#[derive(Debug, Deserialize)]
struct Service {
    #[serde(rename = "@name", default)]
    name: String,
    #[serde(rename = "@product", default)]
    product: String,
    #[serde(rename = "@version", default)]
    version: String,
}

#[derive(Debug, Deserialize)]
struct Script {
    #[serde(rename = "@id")]
    id: String,
    #[serde(rename = "@output")]
    output: String,
    // We could parse structured tables here, but for now raw output is safer
    // table: Option<Table>, 
}

impl NmapScanner {
    pub fn new(
        scripts: Option<String>, 
        stealth: bool, 
        service_detection: bool,
        scan_type: String,
        fragment: bool,
        decoy: Option<String>,
        ports: Option<String>,
        vuln_scan: bool,
    ) -> Self {
        let path = detect_tool("nmap");
        Self {
            nmap_path: path,
            scripts,
            stealth,
            service_detection,
            scan_type,
            fragment,
            decoy,
            ports,
            vuln_scan,
        }
    }
}

#[async_trait]
impl ScannerPlugin for NmapScanner {
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
            remediation_difficulty: crate::plugins::RiskLevel::Low,
            blackarch_category: Some("scanner".to_string()),
            is_destructive: false,
            poc_mode: true,
        }
    }
    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::VulnerabilityScanning]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability("nmap").await)
    }


    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        info!("NmapScanner: launching scan against {}", target.host);
        
        // Defensive validation: ensure target.host is safe even if CLI parsing missed it
        if !TARGET_HOST_RE.is_match(&target.host) || target.host.starts_with('-') {
            warn!("NmapScanner: Skipping invalid/unsafe target: {}", target.host);
            return Ok(Vec::new());
        }

        // P1 FIX: Hardened argument array to prevent command/flag injection
        let mut args = vec!["-n".to_string(), "-Pn".to_string(), "--open".to_string(), "-oX".to_string(), "-".to_string()]; // Output to stdout

        // If specific ports are provided, use -p; otherwise fallback to top-ports
        if let Some(ports) = &self.ports {
            args.push("-p".to_string());
            args.push(ports.clone());
        } else if self.vuln_scan {
            // Vuln hunting: scan 5000 top ports for maximum CVE surface
            args.push("--top-ports".to_string());
            args.push("5000".to_string());
        } else {
            args.push("--top-ports".to_string());
            args.push("3000".to_string());
        }

        if self.stealth {
             args.push("-T2".to_string());
             // Stealth mode timeout: T2 is very slow, max 3 retries
             args.push("--host-timeout".to_string());
             args.push("12h".to_string());
             args.push("--max-retries".to_string());
             args.push("3".to_string());
        } else if self.vuln_scan {
             args.push("-T4".to_string());
             // Vuln scan timeout: 5000 ports + heavy NSE scripts need very generous limits
             // 24h host-timeout to ensure deep scans completion (intensity 9 + scripts)
             args.push("--host-timeout".to_string());
             args.push("24h".to_string());
             args.push("--max-retries".to_string());
             args.push("3".to_string());
        } else {
             args.push("-T4".to_string());
             // Normal mode timeout
             args.push("--host-timeout".to_string());
             args.push("4h".to_string());
             args.push("--max-retries".to_string());
             args.push("2".to_string());
        }

        // P1 & P2 FIXES: Customizable Scan Type, Fragmentation, and Decoys
        args.push(format!("-{}", self.scan_type));
        
        if self.fragment {
            args.push("-f".to_string());
        }
        
        if let Some(decoy) = &self.decoy {
            // Basic validation to prevent arbitrary flag injection via decoy string
            if DECOY_RE.is_match(decoy) && !decoy.starts_with('-') {
                args.push(format!("-D{}", decoy));
            } else {
                warn!("NmapScanner: Skipping invalid decoy string: {}", decoy);
            }
        }

        // --- Vuln Scan Profile: aggressive version + OS detection + NSE suite ---
        if self.vuln_scan {
            // Force service detection with max version intensity
            args.push("-sV".to_string());
            args.push("--version-intensity".to_string());
            args.push("9".to_string());

            // OS fingerprinting (requires root/CAP_NET_RAW)
            args.push("-O".to_string());
            args.push("--osscan-guess".to_string());

            // Comprehensive NSE script suite for vuln hunting
            // vuln: CVE checks (ssl-heartbleed, smb-vuln-*, http-shellshock, etc.)
            // exploit: exploitability verification
            // auth: default credentials, anonymous access
            // default: general enumeration
            // discovery: exposed resources and info disclosure
            args.push("--script=vuln,exploit,auth,default,discovery".to_string());

            // Generous script timeout for heavy scripts like smb-vuln-*
            args.push("--script-timeout".to_string());
            args.push("10m".to_string());

            info!("NmapScanner: 🔴 Vuln Scan profile active — OS detection, version-intensity 9, NSE vuln/exploit/auth/default/discovery");
        } else {
            // Standard behavior: user-controlled service detection and scripts
            if self.service_detection {
                args.push("-sV".to_string());
            }

            if let Some(scripts) = &self.scripts {
                // Further sanitize scripts input (only allows alphanumeric, comma, hyphen)
                if !SCRIPT_RE.is_match(scripts) {
                    warn!("NmapScanner: Skipping unsafe scripts argument: {}", scripts);
                } else {
                    args.push(format!("--script={}", scripts));
                }
            }
        }

        // Final target argument - last index
        // P2 FIX: Use resolved IP if available to avoid double-resolution
        if let Some(ip) = &target.ip {
             args.push(ip.clone());
             info!("NmapScanner: Using resolved IP {} for target {}", ip, target.host);
        } else {
             args.push(target.host.clone());
        }

        let mut child = crate::utils::common::stealth_command(&self.nmap_path)
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to spawn nmap")?;

        let child_pid = child.id().context("Failed to get nmap PID")?;
        let stdout = child.stdout.take().context("Failed to capture nmap stdout")?;
        let std_stdout = tokio_util::io::SyncIoBridge::new(stdout);
        
        let findings_handle = tokio::task::spawn_blocking(move || -> Result<Vec<Finding>> {
            use quick_xml::reader::Reader;
            use quick_xml::events::Event;
            
            let mut reader = Reader::from_reader(std::io::BufReader::new(std_stdout));
            reader.trim_text(true);
            
            let mut local_findings = Vec::new();
            let mut buf = Vec::new();
            const MAX_FINDINGS: usize = 1000; // RAM-FIX: Cap findings to avoid OOM on 1GB VPS
            
            // Streaming parsing state
            let mut current_port: Option<u16> = None;
            let mut current_protocol: String = String::new();
            let mut current_service: Service = Service { name: "unknown".into(), product: "".into(), version: "".into() };

            loop {
                if local_findings.len() >= MAX_FINDINGS {
                    warn!("NmapScanner: Maximum findings limit ({}) reached. Truncating to prevent OOM.", MAX_FINDINGS);
                    break;
                }
                match reader.read_event_into(&mut buf) {
                    Ok(Event::Start(ref e)) => {
                        match e.name().as_ref() {
                            b"port" => {
                                for attr in e.attributes() {
                                    if let Ok(attr) = attr {
                                        if attr.key.as_ref() == b"portid" {
                                            current_port = attr.unescape_value().ok().and_then(|v| v.parse().ok());
                                        } else if attr.key.as_ref() == b"protocol" {
                                            current_protocol = attr.unescape_value().map(|v| v.to_string()).unwrap_or_default();
                                        }
                                    }
                                }
                            }
                            b"service" => {
                                for attr in e.attributes() {
                                    if let Ok(attr) = attr {
                                        match attr.key.as_ref() {
                                            b"name" => current_service.name = attr.unescape_value().map(|v| v.to_string()).unwrap_or_default(),
                                            b"product" => current_service.product = attr.unescape_value().map(|v| v.to_string()).unwrap_or_default(),
                                            b"version" => current_service.version = attr.unescape_value().map(|v| v.to_string()).unwrap_or_default(),
                                            _ => {}
                                        }
                                    }
                                }
                            }
                            b"script" => {
                                let mut id = String::new();
                                let mut output = String::new();
                                for attr in e.attributes() {
                                    if let Ok(attr) = attr {
                                        if attr.key.as_ref() == b"id" {
                                            id = attr.unescape_value().map(|v| v.to_string()).unwrap_or_default();
                                        } else if attr.key.as_ref() == b"output" {
                                            output = attr.unescape_value().map(|v| v.to_string()).unwrap_or_default();
                                        }
                                    }
                                }
                                
                                if let Some(portid) = current_port {
                                    let severity = classify_script_severity(&id, &output);
                                    let category = match severity {
                                        Severity::Critical | Severity::High => Category::Vulnerability,
                                        _ => Category::Misconfiguration,
                                    };
                                    let finding_id = match severity {
                                        Severity::Critical => format!("{}-{}", crate::models::FINDING_VULN_CRITICAL, id),
                                        _ => format!("{}-{}", crate::models::FINDING_NSE_SCRIPT, id),
                                    };
                                    
                                    let mut finding = Finding::new(
                                        &finding_id,
                                        category,
                                        severity.clone(),
                                        &format!("NSE Script {}: {}", id, output.lines().next().unwrap_or("")),
                                        serde_json::json!({ "script_id": id, "output": output, "port": portid })
                                    );
                                    if let Some(rem) = suggest_remediation(&id, &severity) {
                                        finding = finding.with_remediation(&rem);
                                    }
                                    local_findings.push(finding);
                                }
                            }
                            b"osmatch" => {
                                let mut name = String::new();
                                let mut accuracy = String::new();
                                for attr in e.attributes() {
                                    if let Ok(attr) = attr {
                                        if attr.key.as_ref() == b"name" {
                                            name = attr.unescape_value().map(|v| v.to_string()).unwrap_or_default();
                                        } else if attr.key.as_ref() == b"accuracy" {
                                            accuracy = attr.unescape_value().map(|v| v.to_string()).unwrap_or_default();
                                        }
                                    }
                                }
                                local_findings.push(Finding::new(
                                    crate::models::FINDING_OS_DETECTION,
                                    Category::Recon,
                                    Severity::Info,
                                    &format!("OS Detected: {} (accuracy: {}%)", name, accuracy),
                                    serde_json::json!({ "os": name, "accuracy": accuracy })
                                ));
                            }
                            _ => {}
                        }
                    }
                    Ok(Event::End(ref e)) => {
                        if e.name().as_ref() == b"port" {
                            if let Some(portid) = current_port {
                                // Emit the open port finding now that we collected service info
                                local_findings.push(Finding::new(
                                    &format!("{}-{}-{}", crate::models::FINDING_PORT_OPEN, current_protocol, portid),
                                    Category::NetworkPort,
                                    Severity::Info,
                                    &format!("Open Port {}/{}: {} {} {}", portid, current_protocol, current_service.name, current_service.product, current_service.version),
                                    serde_json::json!({
                                        "port": portid,
                                        "protocol": current_protocol,
                                        "service": current_service.name,
                                        "banner": format!("{} {}", current_service.product, current_service.version)
                                    })
                                ));
                            }
                            // Reset per-port state
                            current_port = None;
                            current_protocol.clear();
                            current_service = Service { name: "unknown".into(), product: "".into(), version: "".into() };
                        }
                    }
                    Ok(Event::Eof) => break,
                    Err(e) => return Err(e.into()),
                    _ => {}
                }
                buf.clear();
            }
            Ok(local_findings)
        });

        // Determine max duration for the tokio timeout.
        // It should be slightly higher than the Nmap host-timeout to let Nmap terminate itself gracefully.
        let max_duration = if self.stealth {
             std::time::Duration::from_secs(12 * 3600 + 60) // 12 hours + 1 min
        } else if self.vuln_scan {
             std::time::Duration::from_secs(24 * 3600 + 300) // 24 hours + 5 min
        } else {
             std::time::Duration::from_secs(4 * 3600 + 60) // 4 hours + 1 min
        };

        // Wait for Nmap to exit, with a hard tokio timeout as a failsafe
        let wait_result = tokio::time::timeout(max_duration, child.wait()).await;
        
        let status = match wait_result {
            Ok(Ok(res)) => res,
            Ok(Err(e)) => {
                error!("NmapScanner: Failed to wait for process: {}", e);
                let _ = crate::utils::common::kill_pgid(child_pid).await;
                return Ok(Vec::new());
            }
            Err(_) => {
                error!("NmapScanner: Process timed out at OS level for target: {}", target.host);
                let _ = crate::utils::common::kill_pgid(child_pid).await;
                return Ok(Vec::new());
            }
        };

        if !status.success() {
             error!("Nmap failed on {}", target.host);
             let _ = findings_handle.await;
             return Ok(Vec::new());
        }

        let findings = findings_handle.await??;
        Ok(findings)
    }
}

/// Classify NSE script severity with professional granularity.
fn classify_script_severity(script_id: &str, script_output: &str) -> Severity {
    let id_lower = script_id.to_lowercase();
    let output_lower = script_output.to_lowercase();

    // Critical: known RCE/wormable CVEs and confirmed exploitable states
    for pattern in CRITICAL_PATTERNS.iter() {
        if id_lower.contains(pattern) {
            return Severity::Critical;
        }
    }
    for pattern in CRITICAL_OUTPUT_PATTERNS.iter() {
        if output_lower.contains(pattern) {
            return Severity::Critical;
        }
    }

    // High: general vuln/CVE indicators
    if id_lower.contains("vuln") || id_lower.contains("cve") || output_lower.contains("vulnerable") {
        return Severity::High;
    }

    // Medium: auth/credential issues, enumeration
    for pattern in MEDIUM_PATTERNS.iter() {
        if id_lower.contains(pattern) {
            return Severity::Medium;
        }
    }

    Severity::Info
}

/// Generate contextual remediation advice based on the script finding.
fn suggest_remediation(script_id: &str, severity: &Severity) -> Option<String> {
    match severity {
        Severity::Critical => {
            let id_lower = script_id.to_lowercase();
            if id_lower.contains("ms17-010") || id_lower.contains("eternalblue") {
                Some("CRITICAL: Apply MS17-010 patch immediately. Disable SMBv1. Isolate affected hosts.".into())
            } else if id_lower.contains("heartbleed") {
                Some("CRITICAL: Upgrade OpenSSL to >= 1.0.1g. Revoke and reissue all TLS certificates.".into())
            } else if id_lower.contains("shellshock") {
                Some("CRITICAL: Update Bash to patched version. Review all CGI endpoints.".into())
            } else if id_lower.contains("bluekeep") {
                Some("CRITICAL: Apply CVE-2019-0708 patches. Restrict RDP access via firewall.".into())
            } else {
                Some("CRITICAL: Apply vendor patches immediately. Isolate the service until remediated.".into())
            }
        }
        Severity::High => {
            Some("HIGH: Investigate and patch the identified vulnerability. Review vendor advisories.".into())
        }
        Severity::Medium => {
            let id_lower = script_id.to_lowercase();
            if id_lower.contains("auth") || id_lower.contains("default") || id_lower.contains("brute") {
                Some("MEDIUM: Change default credentials. Enforce strong password policies and MFA.".into())
            } else {
                Some("MEDIUM: Review service configuration. Restrict unnecessary access.".into())
            }
        }
        _ => None,
    }
}

// Helper to avoid deep indentation in the async block
fn process_host(host: &Host, findings: &mut Vec<Finding>) {
    // 0. OS Detection findings
    if let Some(os) = &host.os {
        if let Some(os_matches) = &os.osmatch {
            for os_match in os_matches {
                findings.push(Finding::new(
                    crate::models::FINDING_OS_DETECTION,
                    Category::Recon,
                    Severity::Info,
                    &format!("OS Detected: {} (accuracy: {}%)", os_match.name, os_match.accuracy),
                    serde_json::json!({
                        "os": os_match.name,
                        "accuracy": os_match.accuracy
                    })
                ));
            }
        }
    }

    if let Some(ports) = &host.ports {

        if let Some(port_list) = &ports.port {
            for port in port_list {
                let default_service = Service { name: "unknown".into(), product: "".into(), version: "".into() };
                let svc = port.service.as_ref().unwrap_or(&default_service);
                
                // 1. Port Finding
                findings.push(Finding::new(
                    &format!("{}-{}-{}", crate::models::FINDING_PORT_OPEN, port.protocol, port.portid),
                    Category::NetworkPort,
                    Severity::Info,
                    &format!("Open Port {}/{}: {} {} {}", port.portid, port.protocol, svc.name, svc.product, svc.version),
                    serde_json::json!({
                        "port": port.portid,
                        "protocol": port.protocol,
                        "service": svc.name,
                        "banner": format!("{} {}", svc.product, svc.version)
                    })
                ));

                // 2. Script Findings — with granular severity classification
                if let Some(scripts) = &port.script {
                    for script in scripts {
                         let severity = classify_script_severity(&script.id, &script.output);
                         
                         let category = match severity {
                             Severity::Critical | Severity::High => Category::Vulnerability,
                             Severity::Medium => Category::Misconfiguration,
                             _ => Category::Misconfiguration,
                         };

                         let finding_id = match severity {
                             Severity::Critical => format!("{}-{}", crate::models::FINDING_VULN_CRITICAL, script.id),
                             _ => format!("{}-{}", crate::models::FINDING_NSE_SCRIPT, script.id),
                         };

                         let remediation = suggest_remediation(&script.id, &severity);

                         let mut finding = Finding::new(
                             &finding_id,
                             category,
                             severity,
                             &format!("NSE Script {}: {}", script.id, script.output.lines().next().unwrap_or("")),
                             serde_json::json!({
                                 "script_id": script.id,
                                 "output": script.output,
                                 "port": port.portid
                             })
                         );

                         if let Some(rem) = remediation {
                             finding = finding.with_remediation(&rem);
                         }

                         findings.push(finding);
                    }
                }
            }
        }
    }
}

// Tests
#[cfg(test)]
mod tests {
    use super::*;
    // None needed here

    #[test]
    fn test_nmap_target_validation() {
        // Valid hostnames
        assert!(TARGET_HOST_RE.is_match("google.com"));
        assert!(TARGET_HOST_RE.is_match("sub.domain.local"));
        
        // Valid IPv4
        assert!(TARGET_HOST_RE.is_match("127.0.0.1"));
        
        // Valid IPv6
        assert!(TARGET_HOST_RE.is_match("2001:db8::1"));
        assert!(TARGET_HOST_RE.is_match("::1"));
        assert!(TARGET_HOST_RE.is_match("2001:0db8:85a3:0000:0000:8a2e:0370:7334"));
        
        // Invalid characters
        assert!(!TARGET_HOST_RE.is_match("google.com; rm -rf /"));
        assert!(!TARGET_HOST_RE.is_match("host$name"));
    }
}
