use regex::Regex;
use once_cell::sync::Lazy;

/// OPSEC 2026: Professional Secret Detection Engine.
/// Patterns based on TruffleHog v3 and Gitleaks 2025/2026 catalogs.
pub struct SecretScrubber {
    patterns: Vec<(Regex, &'static str)>,
}

impl SecretScrubber {
    pub fn new() -> Self {
        let mut patterns = Vec::new();
        
        // 1. Database Connection Strings (Preserve structure, redact sensitive parts)
        // Group 1: Protocol, Group 2: User, Group 3: Pass, Group 4: Host, Group 5: Port, Group 6: Path/DB
        if let Ok(re) = Regex::new(r"(?i)(postgresql|mysql|mongodb|redis|sqlserver)://([^:@\s]+):([^@\s]+)@([^:/#\s?]+)(?::(\d+))?(/[^?\s#]*)?") {
            patterns.push((re, "${1}://${2}:[REDACTED_PASSWORD]@[REDACTED_IP]:${5}${6}"));
        }

        // 2. Cloud & SaaS Tokens (High Precision)
        if let Ok(re) = Regex::new(r"AKIA[0-9A-Z]{16}") { patterns.push((re, "[AWS_ACCESS_KEY]")); }
        if let Ok(re) = Regex::new(r"(?i)aws.{0,20}['\x22][0-9a-zA-Z/+]{40}['\x22]") { patterns.push((re, "[AWS_SECRET_KEY]")); }
        if let Ok(re) = Regex::new(r"ghp_[A-Za-z0-9]{36}") { patterns.push((re, "[GITHUB_TOKEN]")); }
        if let Ok(re) = Regex::new(r"xox[baprs]-[0-9a-zA-Z\-]{10,48}") { patterns.push((re, "[SLACK_TOKEN]")); }
        if let Ok(re) = Regex::new(r"AIza[0-9A-Za-z\-_]{35}") { patterns.push((re, "[GOOGLE_API_KEY]")); }
        if let Ok(re) = Regex::new(r"sk_live_[0-9a-zA-Z]{24}") { patterns.push((re, "[STRIPE_SECRET_KEY]")); }
        if let Ok(re) = Regex::new(r"hf_[A-Za-z0-9]{37}") { patterns.push((re, "[HUGGINGFACE_TOKEN]")); }
        
        // 3. JWT and Auth Headers
        if let Ok(re) = Regex::new(r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*") { patterns.push((re, "[JWT_TOKEN]")); }
        if let Ok(re) = Regex::new(r"(?i)(bearer|token|api[_-]?key)['\x22\s:=]+[A-Za-z0-9_\-\.]{16,}") {
            patterns.push((re, "$1\": \"[REDACTED_TOKEN]"));
        }

        // 4. Infrastructure & Internal Topology (RFC 1918)
        if let Ok(re) = Regex::new(r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b") {
            patterns.push((re, "[INTERNAL_IP]"));
        }
        if let Ok(re) = Regex::new(r"\b(127\.0\.0\.1|::1)\b") { patterns.push((re, "[LOCALHOST]")); }

        // 5. Cryptographic Material
        if let Ok(re) = Regex::new(r"(?s)-----BEGIN (RSA|OPENSSH|EC|DSA|PGP) PRIVATE KEY-----.*?-----END \1 PRIVATE KEY-----") {
            patterns.push((re, "[REDACTED_PRIVATE_KEY]"));
        }

        // 6. Generic PII
        if let Ok(re) = Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}") { patterns.push((re, "[REDACTED_EMAIL]")); }

        Self { patterns }
    }

    pub fn scrub(&self, input: &str) -> String {
        let mut result = input.to_string();
        for (re, replacement) in &self.patterns {
            result = re.replace_all(&result, *replacement).to_string();
        }
        result
    }
}

pub static SCRUBBER: Lazy<SecretScrubber> = Lazy::new(SecretScrubber::new);
