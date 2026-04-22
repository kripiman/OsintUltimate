use crate::models::{Finding, Severity, Category};
use serde::Deserialize;
use once_cell::sync::Lazy;
use quick_xml::reader::Reader;
use quick_xml::events::Event;
use anyhow::{Result, Context};
use tracing::{warn, error};
use std::io::BufRead;

// Known critical vulnerability patterns for severity classification
static CRITICAL_PATTERNS: Lazy<Vec<&str>> = Lazy::new(|| vec!["ms17-010", "eternalblue", "heartbleed", "shellshock", "bluekeep", "ms08-067", "ms12-020", "cve-2017", "cve-2018", "cve-2019", "cve-2020", "cve-2021", "cve-2022", "cve-2023", "cve-2024", "cve-2025", "cve-2026", "rce", "remote-code-execution", "command-injection", "smb-vuln-ms17", "smb-vuln-cve", "http-vuln-cve", ]);

static CRITICAL_OUTPUT_PATTERNS: Lazy<Vec<&str>> = Lazy::new(|| vec!["state: vulnerable", "exploitable", "remote code execution", "allows remote attackers", "unauthenticated", ]);

static MEDIUM_PATTERNS: Lazy<Vec<&str>> = Lazy::new(|| vec!["auth", "brute", "default-credentials", "default-password", "weak-password", "anonymous", "enum", "info-disclosure", ]);

// Structs for QuickXML parsing (if needed for non-streaming parts)
#[derive(Debug, Deserialize)]
pub struct NmapRun {
    pub host: Option<Vec<Host>>,
}

#[derive(Debug, Deserialize)]
pub struct Host {
    pub ports: Option<Ports>,
    pub os: Option<Os>,
}

#[derive(Debug, Deserialize)]
pub struct Os {
    pub osmatch: Option<Vec<OsMatch>>,
}

#[derive(Debug, Deserialize)]
pub struct OsMatch {
    #[serde(rename = "@name", default)]
    pub name: String,
    #[serde(rename = "@accuracy", default)]
    pub accuracy: String,
}

#[derive(Debug, Deserialize)]
pub struct Ports {
    pub port: Option<Vec<Port>>,
}

#[derive(Debug, Deserialize)]
pub struct Port {
    #[serde(rename = "@portid")]
    pub portid: u16,
    #[serde(rename = "@protocol")]
    pub protocol: String,
    pub service: Option<Service>,
    pub script: Option<Vec<Script>>, 
}

#[derive(Debug, Deserialize)]
pub struct Service {
    #[serde(rename = "@name", default)]
    pub name: String,
    #[serde(rename = "@product", default)]
    pub product: String,
    #[serde(rename = "@version", default)]
    pub version: String,
}

#[derive(Debug, Deserialize)]
pub struct Script {
    #[serde(rename = "@id")]
    pub id: String,
    #[serde(rename = "@output")]
    pub output: String,
}

/// Classify NSE script severity with professional granularity.
pub fn classify_script_severity(script_id: &str, script_output: &str) -> Severity {
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

/// Generate contextual exploit path advice based on the script finding.
pub fn suggest_exploit_vector(script_id: &str, severity: &Severity) -> Option<String> {
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

/// Streamed parser for Nmap XML output.
pub fn parse_nmap_xml<R: BufRead>(reader: R) -> Result<Vec<Finding>> {
    let mut reader = Reader::from_reader(reader);
    reader.trim_text(true);
    
    let mut local_findings = Vec::new();
    let mut buf = Vec::new();
    const MAX_FINDINGS: usize = 1000; 
    
    // Streaming parsing state
    let mut current_port: Option<u16> = None;
    let mut current_protocol: String = String::new();
    let mut current_service: Service = Service { name: "unknown".into(), product: "".into(), version: "".into() };

    loop {
        if local_findings.len() >= MAX_FINDINGS {
            warn!("NmapParser: Maximum findings limit ({}) reached. Truncating to prevent OOM.", MAX_FINDINGS);
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
                            if let Some(rem) = suggest_exploit_vector(&id, &severity) {
                                finding = finding.with_tactical_path(&rem);
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
}
