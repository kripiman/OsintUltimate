use crate::plugins::ScannerPlugin;
use crate::models::{TargetHost, Finding, Severity, Category};
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::{info, error};
use std::process::Stdio;
use tokio::process::Command;
use quick_xml::de::from_str;
use serde::Deserialize;

pub struct NmapScanner {
    nmap_path: String,
}

// Structs for QuickXML parsing
#[derive(Debug, Deserialize)]
struct NmapRun {
    host: Option<Vec<Host>>, // Meticulous: Can be multiple hosts or None or single
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

impl NmapScanner {
    pub fn new() -> Self {
        let path = which::which("nmap").unwrap_or_else(|_| "nmap".into());
        Self {
            nmap_path: path.to_string_lossy().to_string(),
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
        
        let output = Command::new(&self.nmap_path)
            .args(&[
                "-sS", "-sV",
                "-T4",
                "--open",
                "-n", "-Pn",
                "-oX", "-",
                &target.host
            ])
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
                                }
                            }
                        }
                    }
                }
            },
            Err(e) => {
                error!("Failed to parse Nmap XML: {}", e);
                // Fallback? No, we trust the meticulous parser.
            }
        }
        
        Ok(())
    }
}
