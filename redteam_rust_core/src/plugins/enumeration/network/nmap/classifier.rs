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

/// Generate tactical exploit paths based on the script finding.
pub fn suggest_exploit_vector(script_id: &str, severity: &Severity) -> Option<String> {
    match severity {
        Severity::Critical => {
            let id_lower = script_id.to_lowercase();
            if id_lower.contains("ms17-010") || id_lower.contains("eternalblue") {
                Some("TACTICAL: Use Impacket or Metasploit to verify MS17-010 without crash. Target SMBv1 named pipes.".into())
            } else if id_lower.contains("heartbleed") {
                Some("TACTICAL: Use ssl-heartbleed NSE or custom Python script to leak 64KB memory chunks from TLS heartbeats.".into())
            } else if id_lower.contains("shellshock") {
                Some("TACTICAL: Inject commands via HTTP User-Agent or Referer headers. Test for blind execution via ICMP/DNS.".into())
            } else if id_lower.contains("bluekeep") {
                Some("TACTICAL: Exploit CVE-2019-0708 for unauthenticated RCE. Note: unstable without proper kernel memory layout knowledge.".into())
            } else {
                Some("TACTICAL: Research CVE details for known public PoC. Focus on unauthenticated entry points.".into())
            }
        }
        Severity::High => {
            Some("TACTICAL: High risk vulnerability identified. Pivot to specific CVE exploitation modules.".into())
        }
        Severity::Medium => {
            let id_lower = script_id.to_lowercase();
            if id_lower.contains("auth") || id_lower.contains("default") || id_lower.contains("brute") {
                Some("TACTICAL: Attempt credential stuffing or password spraying using found service metadata.".into())
            } else {
                Some("TACTICAL: Review service configuration for information disclosure or unintended access paths.".into())
            }
        }
        _ => None,
    }
}
