use crate::plugins::ScannerPlugin;
use crate::models::{TargetHost, Finding, Severity, Category};
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::{info, error, warn};
use std::process::Stdio;
use tokio::process::Command;
use quick_xml::de::from_str;
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

        // Output XML
        args.push("-oX".to_string());
        args.push("-".to_string());
        
        // Target
        args.push(target.host.clone());

        let output = Command::new(&self.nmap_path)
            .args(&args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to spawn nmap")?
            .wait_with_output()
            .await?;

        if !output.status.success() {
             let err = String::from_utf8_lossy(&output.stderr);
             error!("Nmap failed: {}", err);
             // Don't error out, just log
             return Ok(());
        }

        let xml_str = String::from_utf8_lossy(&output.stdout);
        
        // Parse XML using quick-xml
        match from_str::<NmapRun>(&xml_str) {
            Ok(run) => {
                if let Some(hosts) = run.host {
                    for host in hosts {
                        if let Some(ports) = host.ports {
                            if let Some(port_list) = ports.port {
                                for port in port_list {
                                    let svc = port.service.unwrap_or(Service { name: "unknown".into(), product: "".into(), version: "".into() });
                                    
                                    // 1. Port Finding
                                    target.findings.push(Finding::new(
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
                                    if let Some(scripts) = port.script {
                                        for script in scripts {
                                             let severity = if script.id.contains("vuln") || script.id.contains("cve") || script.output.to_lowercase().contains("vulnerable") {
                                                 Severity::High
                                             } else {
                                                 Severity::Info // e.g., http-title, ssl-cert
                                             };
                                             
                                             let category = if severity == Severity::High {
                                                 Category::Vulnerability
                                             } else {
                                                 Category::Misconfiguration // or Recon
                                             };

                                             target.findings.push(Finding::new(
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
                }
            },
            Err(e) => {
                error!("Failed to parse Nmap XML: {}", e);
            }
        }
        
        Ok(())
    }
}
