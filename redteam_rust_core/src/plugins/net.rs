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
    pub fn new(scripts: Option<String>, stealth: bool, service_detection: bool) -> Self {
        let path = which::which("nmap").unwrap_or_else(|_| "nmap".into());
        Self {
            nmap_path: path.to_string_lossy().to_string(),
            scripts,
            stealth,
            service_detection,
        }
    }
}

#[async_trait]
impl ScannerPlugin for NmapScanner {
    fn name(&self) -> &'static str {
        "NmapScanner"
    }

    async fn scan(&self, target: &mut TargetHost) -> Result<()> {
        info!("NmapScanner: launching scan against {}", target.host);
        
        // Defensive validation: ensure target.host is safe even if CLI parsing missed it
        if !regex::Regex::new(r"^[a-zA-Z0-9.-]+$").unwrap().is_match(&target.host) || target.host.starts_with('-') {
            warn!("NmapScanner: Skipping invalid/unsafe target: {}", target.host);
            return Ok(());
        }

        let mut args = vec!["-n".to_string(), "-Pn".to_string(), "--open".to_string()];

        // Stealth Mode Logic
        if self.stealth {
             args.push("-T2".to_string());
             args.push("-sS".to_string()); 
             // Stealth usually implies avoiding heavy probing, but -sS is standard.
        } else {
             args.push("-T4".to_string());
             args.push("-sS".to_string());
        }

        // Service Detection
        if self.service_detection {
            args.push("-sV".to_string());
        }

        // Scripts
        if let Some(scripts) = &self.scripts {
            args.push(format!("--script={}", scripts));
            // Scripts often require service detection to work effectively
            if !self.service_detection && !args.contains(&"-sV".to_string()) {
                 warn!("Running scripts without -sV might limit effectiveness.");
                 // We don't force it, user choice.
            }
        }

        // Create a temporary file for XML output
        let temp_file = tempfile::Builder::new()
            .prefix("nmap_scan_")
            .suffix(".xml")
            .tempfile()?;
        let temp_path = temp_file.path().to_owned();

        // Output XML to file
        args.push("-oX".to_string());
        args.push(temp_path.to_string_lossy().to_string());
        
        // Target
        args.push(target.host.clone());

        let output = Command::new(&self.nmap_path)
            .args(&args)
            .stdin(Stdio::null()) // No stdin needed
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to spawn nmap")?
            .wait_with_output()
            .await?;

        if !output.status.success() {
             let err = String::from_utf8_lossy(&output.stderr);
             error!("Nmap failed: {}", err);
             return Ok(());
        }

        // Streaming Parse of XML File
        // We run this in a blocking thread to avoid blocking the async runtime with heavy parsing
        let findings = tokio::task::spawn_blocking(move || -> Result<Vec<Finding>> {
            use std::io::BufReader;
            use quick_xml::de::from_reader; // Import from_reader
            
            // Re-opening for full parse (Simplest robust fix for now)
            // This avoids loading the whole XML string into RAM (String), 
            // instead filtering through BufReader + Struct Deserialization.
            let file = std::fs::File::open(&temp_path)?;
            let reader = BufReader::new(file);
            let run: NmapRun = from_reader(reader)?;
            
            let mut local_findings = Vec::new();
            if let Some(hosts) = run.host {
                 for host in hosts {
                      process_host(&host, &mut local_findings);
                 }
            }
            Ok(local_findings)
        }).await??; // Await spawn_blocking -> Result, then ? the inner Result

        target.findings.extend(findings);
        
        // Temp file is automatically deleted when `temp_file` goes out of scope (at end of function)
        // But we moved path out. `temp_file` is dropped here.
        Ok(())
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
                    &format!("PORT-{}-{}", port.protocol, port.portid),
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
                             &format!("NSE-{}", script.id),
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
