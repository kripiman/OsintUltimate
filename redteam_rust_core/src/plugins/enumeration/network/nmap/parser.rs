use crate::models::{Finding, Category, Severity};
use crate::plugins::enumeration::network::nmap::classifier::{classify_script_severity, map_category, suggest_exploit_vector};
use anyhow::Result;
use quick_xml::reader::Reader;
use quick_xml::events::Event;
use std::io::BufRead;

#[derive(Debug, Default)]
struct ServiceInfo {
    name: String,
    product: String,
    version: String,
}

/// V14.1 Isolated Nmap XML Parser: Streaming events to Findings.
pub fn parse_nmap_xml<R: BufRead>(reader: R) -> Result<Vec<Finding>> {
    let mut reader = Reader::from_reader(reader);
    reader.trim_text(true);
    
    let mut local_findings = Vec::new();
    let mut buf = Vec::new();
    const MAX_FINDINGS: usize = 1000;
    
    let mut current_port: Option<u16> = None;
    let mut current_protocol: String = String::new();
    let mut current_service = ServiceInfo::default();

    loop {
        if local_findings.len() >= MAX_FINDINGS {
            break;
        }
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) => {
                match e.name().as_ref() {
                    b"port" => {
                        for attr in e.attributes().flatten() {
                            if attr.key.as_ref() == b"portid" {
                                current_port = attr.unescape_value().ok().and_then(|v| v.parse().ok());
                            } else if attr.key.as_ref() == b"protocol" {
                                current_protocol = attr.unescape_value().map(|v| v.to_string()).unwrap_or_default();
                            }
                        }
                    }
                    b"service" => {
                        for attr in e.attributes().flatten() {
                            match attr.key.as_ref() {
                                b"name" => current_service.name = attr.unescape_value().map(|v| v.to_string()).unwrap_or_default(),
                                b"product" => current_service.product = attr.unescape_value().map(|v| v.to_string()).unwrap_or_default(),
                                b"version" => current_service.version = attr.unescape_value().map(|v| v.to_string()).unwrap_or_default(),
                                _ => {}
                            }
                        }
                    }
                    b"script" => {
                        let mut id = String::new();
                        let mut output = String::new();
                        for attr in e.attributes().flatten() {
                            if attr.key.as_ref() == b"id" {
                                id = attr.unescape_value().map(|v| v.to_string()).unwrap_or_default();
                            } else if attr.key.as_ref() == b"output" {
                                output = attr.unescape_value().map(|v| v.to_string()).unwrap_or_default();
                            }
                        }
                        
                        if let Some(portid) = current_port {
                            let severity = classify_script_severity(&id, &output);
                            let category = map_category(&severity);
                            let finding_id = if severity == Severity::Critical { 
                                format!("{}-{}", crate::models::FINDING_VULN_CRITICAL, id) 
                            } else { 
                                format!("{}-{}", crate::models::FINDING_NSE_SCRIPT, id) 
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
                        for attr in e.attributes().flatten() {
                            if attr.key.as_ref() == b"name" {
                                name = attr.unescape_value().map(|v| v.to_string()).unwrap_or_default();
                            } else if attr.key.as_ref() == b"accuracy" {
                                accuracy = attr.unescape_value().map(|v| v.to_string()).unwrap_or_default();
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
                    current_port = None;
                    current_protocol.clear();
                    current_service = ServiceInfo::default();
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
