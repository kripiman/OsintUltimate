use crate::plugins::ScannerPlugin;
use crate::models::{TargetHost, Finding, Severity, Category};
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::{info, error, warn};
use std::process::Stdio;
use tokio::process::Command;

use serde::Deserialize;

pub struct NmapScanner {
    nmap_path: String,
    scripts: Option<String>,
    stealth: bool,
    service_detection: bool,
    scan_type: String,
    fragment: bool,
    decoy: Option<String>,
}

// Structs for QuickXML parsing
#[derive(Debug, Deserialize)]
struct NmapRun {
    host: Option<Vec<Host>>,
}

#[derive(Debug, Deserialize)]
struct Host {
    ports: Option<Ports>,
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
    ) -> Self {
        let path = which::which("nmap").unwrap_or_else(|_| "nmap".into());
        Self {
            nmap_path: path.to_string_lossy().to_string(),
            scripts,
            stealth,
            service_detection,
            scan_type,
            fragment,
            decoy,
        }
    }
}

#[async_trait]
impl ScannerPlugin for NmapScanner {
    fn name(&self) -> &'static str {
        crate::models::PLUGIN_NMAP
    }

    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        info!("NmapScanner: launching scan against {}", target.host);
        
        // Defensive validation: ensure target.host is safe even if CLI parsing missed it
        thread_local! {
            static RE: regex::Regex = regex::Regex::new(r"^[a-zA-Z0-9.\-:]+$").unwrap();
        }

        if !RE.with(|re| re.is_match(&target.host)) || target.host.starts_with('-') {
            warn!("NmapScanner: Skipping invalid/unsafe target: {}", target.host);
            return Ok(Vec::new());
        }

        // P1 FIX: Hardened argument array to prevent command/flag injection
        let mut args = vec![
            "-n".to_string(), 
            "-Pn".to_string(), 
            "--open".to_string(),
            "-oX".to_string(),
            "-".to_string(), // Output to stdout
        ];

        if self.stealth {
             args.push("-T2".to_string());
        } else {
             args.push("-T4".to_string());
        }

        // P1 & P2 FIXES: Customizable Scan Type, Fragmentation, and Decoys
        args.push(format!("-{}", self.scan_type));
        
        if self.fragment {
            args.push("-f".to_string());
        }
        
        if let Some(decoy) = &self.decoy {
            // Basic validation to prevent arbitrary flag injection via decoy string
            thread_local! {
                static DECOY_RE: regex::Regex = regex::Regex::new(r"^[a-zA-Z0-9.,_]+$").unwrap();
            }
            if DECOY_RE.with(|re| re.is_match(decoy)) && !decoy.starts_with('-') {
                args.push(format!("-D{}", decoy));
            } else {
                warn!("NmapScanner: Skipping invalid decoy string: {}", decoy);
            }
        }

        if self.service_detection {
            args.push("-sV".to_string());
        }

        if let Some(scripts) = &self.scripts {
            // Further sanitize scripts input (only allows alphanumeric, comma, hyphen)
            thread_local! {
                static SCRIPT_RE: regex::Regex = regex::Regex::new(r"^[a-zA-Z0-9,-]+$").unwrap();
            }
            if !SCRIPT_RE.with(|re| re.is_match(scripts)) {
                warn!("NmapScanner: Skipping unsafe scripts argument: {}", scripts);
            } else {
                args.push(format!("--script={}", scripts));
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

        let mut child = Command::new(&self.nmap_path)
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to spawn nmap")?;

        let stdout = child.stdout.take().context("Failed to capture nmap stdout")?;
        let std_stdout = tokio_util::io::SyncIoBridge::new(stdout);
        
        let findings_handle = tokio::task::spawn_blocking(move || -> Result<Vec<Finding>> {
            use quick_xml::de::from_reader; 
            let reader = std::io::BufReader::new(std_stdout);
            let run: NmapRun = from_reader(reader)?;
            
            let mut local_findings = Vec::new();
            if let Some(hosts) = run.host {
                 for host in hosts {
                      process_host(&host, &mut local_findings);
                 }
            }
            Ok(local_findings)
        });

        // Wait for Nmap to exit indefinitely
        let status = match child.wait().await {
            Ok(res) => res,
            Err(e) => {
                error!("NmapScanner: Failed to wait for process: {}", e);
                let _ = child.kill().await;
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

// Helper to avoid deep indentation in the async block
fn process_host(host: &Host, findings: &mut Vec<Finding>) {
    // Structs are defined in this module, no need to import from crate::models
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

                // 2. Script Findings
                if let Some(scripts) = &port.script {
                    for script in scripts {
                         let severity = if script.id.contains("vuln") || script.id.contains("cve") || script.output.to_lowercase().contains("vulnerable") {
                             Severity::High
                         } else {
                             Severity::Info 
                         };
                         
                         let category = if severity == Severity::High {
                             Category::Vulnerability
                         } else {
                             Category::Misconfiguration 
                         };

                         findings.push(Finding::new(
                             &format!("{}-{}", crate::models::FINDING_NSE_SCRIPT, script.id),
                             category,
                             severity,
                             &format!("NSE Script {}: {}", script.id, script.output.lines().next().unwrap_or("")),
                             serde_json::json!({
                                 "script_id": script.id,
                                 "output": script.output,
                                 "port": port.portid
                             })
                         ));
                    }
                }
            }
        }
    }
}

// Tests
#[cfg(test)]
mod tests {
    // None needed here

    #[test]
    fn test_nmap_target_validation() {
        thread_local! {
            static RE: regex::Regex = regex::Regex::new(r"^[a-zA-Z0-9.\-:]+$").unwrap();
        }
        
        // Valid hostnames
        assert!(RE.with(|re| re.is_match("google.com")));
        assert!(RE.with(|re| re.is_match("sub.domain.local")));
        
        // Valid IPv4
        assert!(RE.with(|re| re.is_match("127.0.0.1")));
        
        // Valid IPv6
        assert!(RE.with(|re| re.is_match("2001:db8::1")));
        assert!(RE.with(|re| re.is_match("::1")));
        assert!(RE.with(|re| re.is_match("2001:0db8:85a3:0000:0000:8a2e:0370:7334")));
        
        // Invalid characters
        assert!(!RE.with(|re| re.is_match("google.com; rm -rf /")));
        assert!(!RE.with(|re| re.is_match("host$name")));
    }
}
