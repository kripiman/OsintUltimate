use crate::models::{Severity, Category};
use once_cell::sync::Lazy;

// Known critical vulnerability patterns for severity classification
static CRITICAL_PATTERNS: Lazy<Vec<&str>> = Lazy::new(|| vec!["ms17-010", "eternalblue", "heartbleed", "shellshock", "bluekeep", "ms08-067", "ms12-020", "cve-2017", "cve-2018", "cve-2019", "cve-2020", "cve-2021", "cve-2022", "cve-2023", "cve-2024", "cve-2025", "cve-2026", "rce", "remote-code-execution", "command-injection", "smb-vuln-ms17", "smb-vuln-cve", "http-vuln-cve", ]);

static CRITICAL_OUTPUT_PATTERNS: Lazy<Vec<&str>> = Lazy::new(|| vec!["state: vulnerable", "exploitable", "remote code execution", "allows remote attackers", "unauthenticated", ]);

static MEDIUM_PATTERNS: Lazy<Vec<&str>> = Lazy::new(|| vec!["auth", "brute", "default-credentials", "default-password", "weak-password", "anonymous", "enum", "info-disclosure", ]);

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

pub fn map_category(severity: &Severity) -> Category {
    match severity {
        Severity::Critical | Severity::High => Category::Vulnerability,
        Severity::Medium => Category::Misconfiguration,
        _ => Category::Misconfiguration,
    }
}

/// Generate contextual remediation advice based on the script finding.
pub fn suggest_remediation(script_id: &str, severity: &Severity) -> Option<String> {
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
