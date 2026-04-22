use regex::Regex;
use once_cell::sync::Lazy;

/// V15 Sovereign Output Shield: Aggressive compression and sanitation for tool outputs.
pub struct CommandFilter {
    generic_rules: Vec<(Regex, &'static str)>,
}

impl Default for CommandFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl CommandFilter {
    pub fn new() -> Self {
        Self {
            generic_rules: vec![
                // 1. Terminal Noise & ANSI sequences
                (Regex::new(r"\x1B\[[0-9;]*[a-zA-Z]").unwrap(), ""), 
                (Regex::new(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]").unwrap(), ""), 
                
                // 2. Generic Progress Spinners/Bars
                (Regex::new(r"(?m)^.*\[[#= ]+\] [0-9]+%.*$").unwrap(), ""), 
                (Regex::new(r"(?m)^.*\[[ \.]*\] [0-9]+%.*$").unwrap(), ""), 
                
                // 3. Legal Boilerplate
                (Regex::new(r"(?mi)^.*(copyright|license|all rights reserved).*$").unwrap(), ""),
                
                // 4. Visual Separators
                (Regex::new(r"(?m)^[.=_\-]{10,}$").unwrap(), ""), 
                (Regex::new(r"(?m)^\s*$").unwrap(), ""),
            ],
        }
    }

    pub fn strip_control_characters(&self, input: &str) -> String {
        input.chars()
            .filter(|&c| !c.is_control() || c == '\n' || c == '\t' || c == '\r')
            .collect()
    }

    pub fn filter(&self, binary: &str, output: &str, _exit_code: i32) -> String {
        // Safety cap: Avoid OOM on massive outputs
        if output.len() > 5 * 1024 * 1024 {
            return format!("[OUTPUT TOO LARGE (>5MB) - Compression Skipped]\n{}", &output[..2000]);
        }

        // Logic for specific tools based on content or binary name
        let mut result = output.to_string();
        
        let binary_lower = binary.to_lowercase();
        if binary_lower.contains("nmap") || output.contains("Nmap scan report") {
            result = self.filter_nmap(&result);
        } else if binary_lower.contains("nuclei") || output.contains("[nuclei]") {
            result = self.filter_nuclei(&result);
        }

        // Apply Generic Rules
        for (re, replacement) in &self.generic_rules {
            result = re.replace_all(&result, *replacement).to_string();
        }

        result.lines()
            .filter(|line| !line.trim().is_empty())
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn filter_nmap(&self, input: &str) -> String {
        let re_junk = Regex::new(r"(?m)^(NSE: |Service scan transition|Initiating |Scanning |Completed ).*$").unwrap();
        re_junk.replace_all(input, "").to_string()
    }

    fn filter_nuclei(&self, input: &str) -> String {
        let lines: Vec<&str> = input.lines()
            .filter(|l| l.contains("[") && (l.contains("INF") || l.contains("WRN") || l.contains("CRT") || l.contains("HIGH")))
            .collect();
        lines.join("\n")
    }
}

/// SecurityGuard: Redacts sensitive secrets from strings (logs and agent context).
pub struct SecurityGuard;

impl SecurityGuard {
    pub fn redact_secrets(input: &str) -> String {
        let mut result = input.to_string();

        static RE_PATTERNS: Lazy<Vec<(Regex, &'static str)>> = Lazy::new(|| vec![
            (Regex::new(r"(?i)sk-ant-api03-[a-zA-Z0-9-_]{93}").unwrap(), "[REDACTED_ANTHROPIC_KEY]"),
            (Regex::new(r"(?i)(ghp|gho|ghs|ghr|github_pat)_[a-zA-Z0-9]{36,255}").unwrap(), "[REDACTED_GITHUB_TOKEN]"),
            (Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(), "[REDACTED_AWS_KEY]"),
            (Regex::new(r"eyJ[a-zA-Z0-9_-]{15,}(\.[a-zA-Z0-9_-]{10,})*").unwrap(), "[REDACTED_JWT]"),
            (Regex::new(r"(?i)(postgres|mysql|mongodb|redis|mssql)://[a-zA-Z0-9._-]+:[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+").unwrap(), "[REDACTED_DB_URL]"),
            (Regex::new(r"-----BEGIN (RSA|OPENSSH|PRIVATE) KEY-----[\s\S]*?-----END (RSA|OPENSSH|PRIVATE) KEY-----").unwrap(), "[REDACTED_PRIVATE_KEY]"),
        ]);

        for (re, placeholder) in RE_PATTERNS.iter() {
            result = re.replace_all(&result, *placeholder).to_string();
        }

        result
    }
}

pub static COMMAND_FILTER: Lazy<CommandFilter> = Lazy::new(CommandFilter::new);
