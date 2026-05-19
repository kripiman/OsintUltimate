use crate::models::{Finding, Severity, Category};
use std::fmt::Write;

pub(super) fn severity_label(s: &Severity) -> &'static str {
    match s {
        Severity::Critical => "Critical (P1)",
        Severity::High     => "High (P2)",
        Severity::Medium   => "Medium (P3)",
        Severity::Low      => "Low (P4)",
        Severity::Info     => "Informational (P5)",
    }
}

pub(super) fn default_impact(s: &Severity) -> &'static str {
    match s {
        Severity::Critical => "An attacker could fully compromise the affected system or data, leading to complete loss of confidentiality, integrity, or availability.",
        Severity::High     => "An attacker could gain significant unauthorized access or cause substantial damage to the affected system or its users.",
        Severity::Medium   => "An attacker could obtain sensitive information or perform actions that partially compromise the security of the affected system.",
        _                  => "Limited security impact. No immediate risk to users or data.",
    }
}

pub(super) fn default_remediation(_severity: &Severity, category: &Category) -> &'static str {
    match category {
        Category::Vulnerability => "Implement robust input validation and output encoding. Ensure all software components are patched to the latest version.",
        Category::Misconfiguration => "Review the configuration against security benchmarks (e.g., CIS). Disable unnecessary services and implement the principle of least privilege.",
        Category::CredentialLeak => "Revoke the leaked credentials immediately and rotate them. Enable MFA and investigate if the credentials were used for unauthorized access.",
        Category::Idor => "Implement proper access control checks at the object level. Ensure users can only access resources they are authorized to view.",
        Category::FileUploadVulnerability => "Restrict allowed file types, implement strict filename validation, and store uploaded files in a non-executable directory.",
        _ => "Investigate the finding and apply necessary security controls or patches according to organizational policy."
    }
}

pub(super) struct HttpEvidence<'a> {
    pub(super) raw_request: Option<&'a str>,
    pub(super) raw_response: Option<&'a str>,
}

pub(super) fn http_evidence_view(finding: &Finding) -> HttpEvidence<'_> {
    let data = finding.evidence.primary.as_ref().map(|e| &e.data);
    HttpEvidence {
        raw_request: data.and_then(|d| d.get("raw_request")).and_then(|v| v.as_str()),
        raw_response: data.and_then(|d| d.get("raw_response")).and_then(|v| v.as_str()),
    }
}

/// Parses a raw HTTP request and returns a formatted curl command.
pub(super) fn build_curl_from_raw(raw: &str, default_host: &str) -> Option<String> {
    let mut lines = raw.lines();
    let first_line = lines.next()?;
    let mut parts = first_line.split_whitespace();
    
    let method = parts.next()?;
    let path = parts.next()?;
    
    let mut headers = Vec::new();
    let mut host = default_host.to_string();
    let mut body = String::new();
    let mut reading_body = false;

    for line in lines {
        if reading_body {
            body.push_str(line);
            body.push('\n');
            continue;
        }

        if line.is_empty() {
            reading_body = true;
            continue;
        }

        if let Some((key, value)) = line.split_once(':') {
            let key = key.trim();
            let value = value.trim();
            if key.eq_ignore_ascii_case("Host") {
                host = value.to_string();
            }
            if !key.eq_ignore_ascii_case("Content-Length") {
                headers.push((key.to_string(), value.to_string()));
            }
        }
    }

    let url = if path.starts_with("http") {
        path.to_string()
    } else {
        format!("https://{}{}", host, path)
    };

    let mut curl = format!("curl -i -s -k -X {}", method);
    
    for (k, v) in headers {
        let _ = write!(curl, " \\\n  -H \"{}: {}\"", k, v.replace('\"', "\\\""));
    }

    if !body.trim().is_empty() {
        let escaped_body = body.trim().replace('\'', "'\\''");
        let _ = write!(curl, " \\\n  --data-raw '{}'", escaped_body);
    }

    let escaped_url = url.replace('\'', "'\\''");
    let _ = write!(curl, " \\\n  '{}'", escaped_url);

    Some(curl)
}
