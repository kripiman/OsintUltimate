use regex::Regex;
use once_cell::sync::Lazy;

/// OPSEC 2026: Professional Secret Detection Engine.
/// Patterns based on TruffleHog v3 and Gitleaks 2025/2026 catalogs.
pub struct SecretScrubber {
    patterns: Vec<(Regex, &'static str)>,
}

impl Default for SecretScrubber {
    fn default() -> Self {
        Self::new()
    }
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
        if let Ok(re) = Regex::new(r"gh[osrp]_[A-Za-z0-9]{36,255}") { patterns.push((re, "[GITHUB_TOKEN]")); }
        if let Ok(re) = Regex::new(r"github_pat_[A-Za-z0-9_]{82}") { patterns.push((re, "[GITHUB_PAT]")); }
        if let Ok(re) = Regex::new(r"xox[baprs]-[0-9a-zA-Z\-]{10,48}") { patterns.push((re, "[SLACK_TOKEN]")); }
        if let Ok(re) = Regex::new(r"AIza[0-9A-Za-z\-_]{35}") { patterns.push((re, "[GOOGLE_API_KEY]")); }
        if let Ok(re) = Regex::new(r"ya29\.[a-zA-Z0-9_-]{50,}") { patterns.push((re, "[GOOGLE_OAUTH]")); }
        if let Ok(re) = Regex::new(r"[rs]k_(live|test)_[0-9a-zA-Z]{24}") { patterns.push((re, "[STRIPE_KEY]")); }
        if let Ok(re) = Regex::new(r"hf_[A-Za-z0-9]{34,}") { patterns.push((re, "[HUGGINGFACE_TOKEN]")); }
        if let Ok(re) = Regex::new(r"npm_[A-Za-z0-9]{36}") { patterns.push((re, "[NPM_TOKEN]")); }
        if let Ok(re) = Regex::new(r"sk-ant-api03-[A-Za-z0-9\-_]{93}") { patterns.push((re, "[ANTHROPIC_KEY]")); }
        
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
        if let Ok(re) = Regex::new(r"(?s)-----BEGIN (?:RSA|OPENSSH|EC|DSA|PGP) PRIVATE KEY-----.*?-----END (?:RSA|OPENSSH|EC|DSA|PGP) PRIVATE KEY-----") {
            patterns.push((re, "[REDACTED_PRIVATE_KEY]"));
        }

        // 6. Generic PII
        if let Ok(re) = Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}") { patterns.push((re, "[REDACTED_EMAIL]")); }

        // 7. System Paths & Host Topology (Hardened)
        if let Ok(re) = Regex::new(r"(?i)\b(/etc/passwd|/etc/shadow|/etc/group|/etc/hosts|/root/\.ssh/id_rsa)\b") {
            patterns.push((re, "[REDACTED_SYSTEM_PATH]"));
        }
        if let Ok(re) = Regex::new(r"(?i)\b(C:\\Windows\\System32\\Config\\SAM|C:\\Windows\\win\.ini|C:\\Users\\.*\\\.ssh\\id_rsa)\b") {
            patterns.push((re, "[REDACTED_WINDOWS_PATH]"));
        }

        // 8. Control Injection Prevention (Anti-Hallucination)
        // Evita que la herramienta inyecte cabeceras falsas que confundan al parseador TONE/LLM
        if let Ok(re) = Regex::new(r"(?m)^#type:tone-v\d+.*$") { patterns.push((re, "[REDACTED_MALICIOUS_HEADER]")); }
        if let Ok(re) = Regex::new(r"(?m)^---.*?\btemplate\b.*?\b(title|severity)\b.*?---$") { patterns.push((re, "[REDACTED_MALICIOUS_METADATA]")); }

        Self { patterns }
    }

    /// GAP-9: Sensitive Path Guard.
    /// Detecta si una cadena contiene rutas o nombres de archivos críticos que no deben enviarse a la IA.
    pub fn is_sensitive_content(&self, input: &str) -> bool {
        static SENSITIVE_TOKENS: &[&str] = &[
            ".env", "id_rsa", "shadow", "passwd", "config.php", "settings.py",
            "credentials", "secrets.yaml", "wp-config.php", ".git/config",
            "access_key", "secret_key", "api_key", "token"
        ];
        
        let lower = input.to_lowercase();
        for token in SENSITIVE_TOKENS {
            if lower.contains(token) {
                return true;
            }
        }
        false
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
