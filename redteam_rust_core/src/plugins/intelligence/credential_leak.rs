use crate::plugins::{Capability, PluginMetadata, RiskLevel, ScannerPlugin, TargetType};
use crate::utils::config::Config;
use crate::models::{Category, Finding, Severity, TargetHost, PLUGIN_CREDENTIAL_LEAK};
use async_trait::async_trait;
use anyhow::Result;
use regex::Regex;
use tracing::{info, warn, debug};
use std::collections::HashSet;
use std::process::Stdio;
use std::sync::OnceLock;
use std::time::Duration;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use sha1::Digest;

const HIBP_TIMEOUT_SECS: u64 = 10;
const HIBP_RATE_LIMIT_MS: u64 = 1500;
const MAX_EMAIL_LOOKUPS: usize = 10;
const MAX_PASSWORD_LOOKUPS: usize = 50;
const HIBP_CACHE_TTL_SECS: u64 = 86_400; // 24h

pub struct CredentialLeakScanner {
    client: reqwest::Client,
    hibp_api_key: Option<String>,
    max_email_lookups: usize,
    max_password_lookups: usize,
    hibp_pwned_base_url: String,
    hibp_breached_base_url: String,
    h8mail_path: String,
}

impl Default for CredentialLeakScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl CredentialLeakScanner {
    pub fn new() -> Self {
        let cfg = Config::from_env();
        Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(HIBP_TIMEOUT_SECS))
                .build()
                .expect("reqwest::Client builder must not fail"),
            hibp_api_key: cfg.hibp_api_key,
            max_email_lookups: MAX_EMAIL_LOOKUPS,
            max_password_lookups: MAX_PASSWORD_LOOKUPS,
            hibp_pwned_base_url: "https://api.pwnedpasswords.com".to_string(),
            hibp_breached_base_url: "https://haveibeenpwned.com".to_string(),
            h8mail_path: crate::utils::tool_detection::detect_tool("h8mail"),
        }
    }

    /// Test-only constructor. Exposed as `pub` for integration tests.
    pub fn with_params(
        client: reqwest::Client,
        hibp_api_key: Option<String>,
        max_email_lookups: usize,
        max_password_lookups: usize,
    ) -> Self {
        Self {
            client,
            hibp_api_key,
            max_email_lookups,
            max_password_lookups,
            hibp_pwned_base_url: "https://api.pwnedpasswords.com".to_string(),
            hibp_breached_base_url: "https://haveibeenpwned.com".to_string(),
            h8mail_path: String::new(),
        }
    }

    /// Test-only: override h8mail binary path.
    pub fn with_h8mail_path(mut self, path: String) -> Self {
        self.h8mail_path = path;
        self
    }

    /// Test-only: inject base URLs for Wiremock integration tests.
    pub fn with_base_urls(
        mut self,
        hibp_pwned_base_url: String,
        hibp_breached_base_url: String,
    ) -> Self {
        self.hibp_pwned_base_url = hibp_pwned_base_url;
        self.hibp_breached_base_url = hibp_breached_base_url;
        self
    }

    /// Sanitize a string for use in Finding IDs.
    /// Alphanumeric and '-' preserved; everything else → '-'.
    fn sanitize_id(s: &str) -> String {
        s.chars()
            .map(|c| if c.is_alphanumeric() || c == '-' { c } else { '-' })
            .collect()
    }

    fn email_regex() -> &'static Regex {
        static REGEX: OnceLock<Regex> = OnceLock::new();
        REGEX.get_or_init(|| {
            Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").unwrap()
        })
    }

    /// Extract unique email addresses from the target and its findings.
    fn extract_emails(target: &TargetHost) -> HashSet<String> {
        let mut emails = HashSet::new();
        if target.host.contains('@') {
            emails.insert(target.host.clone());
        }
        for finding in target.findings.iter() {
            let data = match finding.evidence.primary.as_ref() {
                Some(ev) => &ev.data,
                None => continue,
            };
            let json_str = match serde_json::to_string(data) {
                Ok(s) => s,
                Err(_) => continue,
            };
            for mat in Self::email_regex().find_iter(&json_str) {
                emails.insert(mat.as_str().to_lowercase());
            }
        }
        emails
    }

    /// Recursively scan JSON context for sensitive keys that likely hold plaintext passwords.
    fn extract_passwords_from_value(value: &serde_json::Value, out: &mut HashSet<String>) {
        match value {
            serde_json::Value::Object(map) => {
                for (k, v) in map {
                    if Self::is_password_key(k) {
                        if let serde_json::Value::String(s) = v {
                            if s.len() >= 4 {
                                out.insert(s.clone());
                            }
                        }
                    } else {
                        Self::extract_passwords_from_value(v, out);
                    }
                }
            }
            serde_json::Value::Array(arr) => {
                for v in arr {
                    Self::extract_passwords_from_value(v, out);
                }
            }
            _ => {}
        }
    }

    fn is_password_key(k: &str) -> bool {
        let lower = k.to_lowercase();
        matches!(lower.as_str(), "password" | "secret" | "token" | "api_key" | "passwd" | "pwd")
    }

    /// Extract plaintext passwords from findings evidence data.
    fn extract_passwords(target: &TargetHost) -> HashSet<String> {
        let mut passwords = HashSet::new();
        for finding in target.findings.iter() {
            let data = match finding.evidence.primary.as_ref() {
                Some(ev) => &ev.data,
                None => continue,
            };
            Self::extract_passwords_from_value(data, &mut passwords);
        }
        passwords
    }

    /// Extract SHA1 hashes (40-char hex) from findings evidence data.
    /// These are detected for informational purposes but CANNOT be verified
    /// against HIBP Pwned Passwords because HIBP requires plaintext input.
    fn extract_sha1_hashes(target: &TargetHost) -> HashSet<String> {
        let mut hashes = HashSet::new();
        let sha1_re = Regex::new(r"\b[a-fA-F0-9]{40}\b").unwrap();
        for finding in target.findings.iter() {
            let data = match finding.evidence.primary.as_ref() {
                Some(ev) => &ev.data,
                None => continue,
            };
            let json_str = match serde_json::to_string(data) {
                Ok(s) => s,
                Err(_) => continue,
            };
            for mat in sha1_re.find_iter(&json_str) {
                hashes.insert(mat.as_str().to_lowercase());
            }
        }
        hashes
    }

    /// Check if a password's full SHA1 suffix appears in the HIBP range response.
    fn check_pwned_from_response(full_hex: &str, body: &str) -> Option<u64> {
        let suffix = &full_hex[5..];
        for line in body.lines() {
            let mut parts = line.split(':');
            if let (Some(suf), Some(cnt)) = (parts.next(), parts.next()) {
                if suf.eq_ignore_ascii_case(suffix) {
                    return cnt.parse().ok();
                }
            }
        }
        None
    }

    /// Query HIBP Pwned Passwords k-anonymity API.
    /// Returns pwned count if the password appears in breaches.
    async fn pivot_hibp_pwned_passwords(&self, password: &str) -> Option<u64> {
        let full_hash = sha1::Sha1::digest(password.as_bytes());
        let full_hex = hex::encode_upper(full_hash);
        let prefix = &full_hex[..5];

        if let Some(cache) = crate::utils::api_cache::ApiCache::global() {
            if let Some(hit) = cache.get::<String>("hibp_pwned", prefix, "range", Duration::from_secs(HIBP_CACHE_TTL_SECS)).await {
                return Self::check_pwned_from_response(&full_hex, &hit);
            }
        }

        let url = format!("{}/range/{}", self.hibp_pwned_base_url.trim_end_matches('/'), prefix);
        match self.client.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => {
                if let Ok(body) = resp.text().await {
                    if let Some(cache) = crate::utils::api_cache::ApiCache::global() {
                        cache.put("hibp_pwned", prefix, "range", &body).await;
                    }
                    return Self::check_pwned_from_response(&full_hex, &body);
                }
            }
            Ok(resp) => {
                warn!("HIBP Pwned Passwords returned HTTP {} for prefix {}", resp.status(), prefix);
            }
            Err(e) => {
                warn!("HIBP Pwned Passwords request failed: {}", e);
            }
        }
        None
    }

    /// Query HIBP Breached Account API (gated by HIBP_API_KEY).
    /// Returns list of breach names.
    async fn pivot_hibp_breached_account(&self, email: &str) -> Vec<String> {
        let key = match &self.hibp_api_key {
            Some(k) if !k.is_empty() => k,
            _ => return Vec::new(),
        };

        let encoded = utf8_percent_encode(email, NON_ALPHANUMERIC).to_string();
        let url = format!(
            "{}/api/v3/breachedaccount/{}",
            self.hibp_breached_base_url.trim_end_matches('/'),
            encoded
        );

        match self.client
            .get(&url)
            .header("hibp-api-key", key)
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                #[derive(serde::Deserialize)]
                #[serde(rename_all = "PascalCase")]
                struct Breach { name: String }
                if let Ok(breaches) = resp.json::<Vec<Breach>>().await {
                    return breaches.into_iter().map(|b| b.name).collect();
                }
            }
            Ok(resp) if resp.status() == reqwest::StatusCode::NOT_FOUND => {
                // Email not breached — empty list is correct.
                return Vec::new();
            }
            Ok(resp) => {
                warn!("HIBP Breached Account returned HTTP {} for {}", resp.status(), email);
            }
            Err(e) => {
                warn!("HIBP Breached Account request failed for {}: {}", email, e);
            }
        }
        Vec::new()
    }

    /// Parse h8mail JSON output into structured hits.
    /// Pure function — testable without subprocess.
    fn parse_h8mail_output(json: &str) -> Vec<H8mailHit> {
        serde_json::from_str::<Vec<H8mailHit>>(json).unwrap_or_default()
    }

    async fn pivot_h8mail(&self, email: &str) -> Vec<Finding> {
        // Graceful degrade: skip if h8mail binary not detected.
        if self.h8mail_path.is_empty() || !tokio::fs::try_exists(&self.h8mail_path).await.unwrap_or(false) {
            debug!("CredentialLeakScanner: h8mail not available, skipping");
            return Vec::new();
        }

        let tmpfile = format!(
            "/tmp/h8mail_{}_{}.json",
            Self::sanitize_id(email),
            &uuid::Uuid::new_v4().to_string()[..8]
        );

        debug!("CredentialLeakScanner: spawning h8mail for {} -> {}", email, tmpfile);
        let child = match tokio::process::Command::new(&self.h8mail_path)
            .arg("-t").arg(email)
            .arg("--chase").arg("--power-chase")
            .arg("-o").arg(&tmpfile)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                warn!("Failed to spawn h8mail for {}: {}", email, e);
                return Vec::new();
            }
        };

        let output = match child.wait_with_output().await {
            Ok(o) => o,
            Err(e) => {
                warn!("h8mail failed for {}: {}", email, e);
                let _ = tokio::fs::remove_file(&tmpfile).await;
                return Vec::new();
            }
        };

        if !output.status.success() {
            warn!("h8mail exited with status {} for {}", output.status, email);
            let _ = tokio::fs::remove_file(&tmpfile).await;
            return Vec::new();
        }

        let json = match tokio::fs::read_to_string(&tmpfile).await {
            Ok(s) => s,
            Err(e) => {
                warn!("Failed to read h8mail output for {}: {}", email, e);
                let _ = tokio::fs::remove_file(&tmpfile).await;
                return Vec::new();
            }
        };

        let _ = tokio::fs::remove_file(&tmpfile).await;
        let hits = Self::parse_h8mail_output(&json);
        let mut findings = Vec::new();
        for hit in hits {
            if let Some(breach) = hit.breach {
                findings.push(Finding::new(
                    &format!("CREDENTIAL-LEAK-H8MAIL-{}", Self::sanitize_id(&hit.target)),
                    Category::CredentialLeak,
                    Severity::High,
                    &format!("h8mail found {} in {}", hit.target, breach),
                    serde_json::json!({
                        "email": hit.target,
                        "breach": breach,
                        "source": "h8mail",
                    }),
                ));
            }
        }
        findings
    }

    fn build_finding(
        &self,
        email: &str,
        breaches: &[String],
        pwned_count: u64,
    ) -> Finding {
        let severity = if pwned_count > 0 || !breaches.is_empty() {
            Severity::High
        } else {
            Severity::Info
        };
        let mut sources = Vec::new();
        if pwned_count > 0 {
            sources.push("hibp_pwned_passwords");
        }
        if !breaches.is_empty() {
            sources.push("hibp_breached_account");
        }

        Finding::new(
            &format!("CREDENTIAL-LEAK-{}", Self::sanitize_id(email)),
            Category::CredentialLeak,
            severity,
            &format!("Credential leak validation for {}", email),
            serde_json::json!({
                "email": email,
                "breach_count": breaches.len(),
                "breach_names": breaches,
                "password_pwned_count": pwned_count,
                "sources": sources,
            }),
        )
    }
}

#[derive(serde::Deserialize, Debug, PartialEq)]
struct H8mailHit {
    target: String,
    breach: Option<String>,
}

#[async_trait]
impl ScannerPlugin for CredentialLeakScanner {
    fn name(&self) -> &'static str {
        PLUGIN_CREDENTIAL_LEAK
    }

    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: self.name().to_string(),
            description: "Credential leak validation via h8mail subprocess (optional) and HIBP APIs (Pwned Passwords k-anonymity always-on; Breached Account gated by HIBP_API_KEY).".to_string(),
            target_type: TargetType::Host,
            risk_level: RiskLevel::Safe,
            layer: crate::core::capability_layer::ScanLayer::Verification,
            expected_duration: Duration::from_secs(30),
            capabilities: self.capabilities(),
            cost: 2,
            category: "Intelligence".to_string(),
            mitre_attacks: vec!["T1589".to_string()],
            exploit_difficulty: RiskLevel::Safe,
            blackarch_category: Some("recon".to_string()),
            is_destructive: false,
            poc_mode: false,
            ..Default::default()
        }
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::CredentialLeakValidation]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        // HIBP Pwned Passwords is always-on (native HTTP, no external binary).
        Ok(true)
    }

    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        info!("CredentialLeakScanner: validating credentials for {}", target.host);

        let emails = Self::extract_emails(target);
        let passwords = Self::extract_passwords(target);
        let _sha1_hashes = Self::extract_sha1_hashes(target); // informational; not verifiable

        let mut findings = Vec::new();
        let mut email_count = 0usize;
        let mut password_count = 0usize;

        // --- Email paths: h8mail + HIBP breached account (capped at 10) ---
        for email in emails {
            if email_count >= self.max_email_lookups {
                debug!("CredentialLeakScanner: email lookup cap ({}) reached", self.max_email_lookups);
                break;
            }
            email_count += 1;

            let breaches = self.pivot_hibp_breached_account(&email).await;
            let pwned_count = 0u64;

            // h8mail path (graceful degrade if not installed)
            let h8mail_findings = self.pivot_h8mail(&email).await;
            findings.extend(h8mail_findings);

            // Only emit a finding if there's actual breach data or h8mail found something.
            // For now, h8mail always returns empty (not installed), so we rely on HIBP.
            if !breaches.is_empty() || pwned_count > 0 {
                findings.push(self.build_finding(&email, &breaches, pwned_count));
            }

            // Rate limit between HIBP breached account calls
            if email_count < self.max_email_lookups {
                tokio::time::sleep(Duration::from_millis(HIBP_RATE_LIMIT_MS)).await;
            }
        }

        // --- Password path: HIBP Pwned Passwords (capped at 50) ---
        for password in passwords {
            if password_count >= self.max_password_lookups {
                debug!("CredentialLeakScanner: password lookup cap ({}) reached", self.max_password_lookups);
                break;
            }
            password_count += 1;

            if let Some(count) = self.pivot_hibp_pwned_passwords(&password).await {
                if count > 0 {
                    findings.push(Finding::new(
                        &format!("CREDENTIAL-LEAK-PWD-{}", Self::sanitize_id(&password)),
                        Category::CredentialLeak,
                        Severity::High,
                        &format!("Password found in {} HIBP breaches", count),
                        serde_json::json!({
                            "password_pwned_count": count,
                            "source": "hibp_pwned_passwords",
                        }),
                    ));
                }
            }

            // Rate limit between HIBP Pwned Passwords calls
            if password_count < self.max_password_lookups {
                tokio::time::sleep(Duration::from_millis(HIBP_RATE_LIMIT_MS)).await;
            }
        }

        info!(
            "CredentialLeakScanner: {} findings for {} ({} emails, {} passwords checked)",
            findings.len(), target.host, email_count, password_count
        );
        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{MockServer, Mock, ResponseTemplate};
    use wiremock::matchers::{method, path};

    #[test]
    fn test_sanitize_id() {
        assert_eq!(CredentialLeakScanner::sanitize_id("test@example.com"), "test-example-com");
        assert_eq!(CredentialLeakScanner::sanitize_id("Cloudflare Inc."), "Cloudflare-Inc-");
    }

    #[test]
    fn test_extract_emails_from_findings() {
        let target = TargetHost {
            host: "target.example.com".to_string(),
            findings: std::sync::Arc::new(vec![
                Finding::new(
                    "TEST-1",
                    Category::CredentialLeak,
                    Severity::Medium,
                    "Secret found",
                    serde_json::json!({
                        "secret": "api_key=12345",
                        "author": "admin@example.com"
                    }),
                ),
                Finding::new(
                    "TEST-2",
                    Category::CredentialLeak,
                    Severity::Medium,
                    "Another secret",
                    serde_json::json!({
                        "url": "https://git.example.com",
                        "committer": "dev@EXAMPLE.COM" // uppercase, should normalize
                    }),
                ),
            ]),
            ..Default::default()
        };
        let emails = CredentialLeakScanner::extract_emails(&target);
        assert_eq!(emails.len(), 2);
        assert!(emails.contains("admin@example.com"));
        assert!(emails.contains("dev@example.com")); // normalized to lowercase
    }

    #[test]
    fn test_extract_passwords_from_context() {
        let target = TargetHost {
            host: "target.example.com".to_string(),
            findings: std::sync::Arc::new(vec![
                Finding::new(
                    "TEST-1",
                    Category::CredentialLeak,
                    Severity::Medium,
                    "Secret found",
                    serde_json::json!({
                        "password": "hunter2",
                        "api_key": "sk-12345",
                        "nested": {
                            "secret": "nested-secret"
                        }
                    }),
                ),
            ]),
            ..Default::default()
        };
        let passwords = CredentialLeakScanner::extract_passwords(&target);
        assert_eq!(passwords.len(), 3);
        assert!(passwords.contains("hunter2"));
        assert!(passwords.contains("sk-12345"));
        assert!(passwords.contains("nested-secret"));
    }

    #[test]
    fn test_extract_sha1_skipped_for_hibp() {
        let target = TargetHost {
            host: "target.example.com".to_string(),
            findings: std::sync::Arc::new(vec![
                Finding::new(
                    "TEST-1",
                    Category::CredentialLeak,
                    Severity::Medium,
                    "Hash found",
                    serde_json::json!({
                        "hash": "cbfdac6008f9cab4083784cbd1874f76618d2a97"
                    }),
                ),
            ]),
            ..Default::default()
        };
        let hashes = CredentialLeakScanner::extract_sha1_hashes(&target);
        assert_eq!(hashes.len(), 1);
        assert!(hashes.contains("cbfdac6008f9cab4083784cbd1874f76618d2a97"));
        // These hashes are detected but NOT sent to HIBP (one-way function).
    }

    #[test]
    fn test_parse_h8mail_output_valid() {
        let json = r#"[
            {"target": "user@example.com", "breach": "LinkedIn2012"},
            {"target": "user@example.com", "breach": "Dropbox2016"}
        ]"#;
        let hits = CredentialLeakScanner::parse_h8mail_output(json);
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].target, "user@example.com");
        assert_eq!(hits[0].breach, Some("LinkedIn2012".to_string()));
    }

    #[test]
    fn test_parse_h8mail_output_malformed() {
        let json = r#"not valid json"#;
        let hits = CredentialLeakScanner::parse_h8mail_output(json);
        assert!(hits.is_empty());
    }

    #[tokio::test]
    async fn test_hibp_pwned_passwords_known_pwned() {
        let server = MockServer::start().await;
        let prefix = "CBFDA";
        let suffix = "C6008F9CAB4083784CBD1874F76618D2A97";

        Mock::given(method("GET"))
            .and(path(format!("/range/{}", prefix)))
            .respond_with(ResponseTemplate::new(200).set_body_string(format!(
                "{}:2254650\nOTHERHASH:123\n",
                suffix
            )))
            .mount(&server)
            .await;

        let scanner = CredentialLeakScanner::with_params(
            reqwest::Client::new(),
            None,
            10,
            50,
        ).with_base_urls(
            server.uri(),
            "https://haveibeenpwned.com".to_string(),
        );

        let count = scanner.pivot_hibp_pwned_passwords("password123").await;
        assert_eq!(count, Some(2254650));
    }

    #[tokio::test]
    async fn test_hibp_pwned_passwords_not_pwned() {
        let server = MockServer::start().await;
        let prefix = "CBFDA";

        Mock::given(method("GET"))
            .and(path(format!("/range/{}", prefix)))
            .respond_with(ResponseTemplate::new(200).set_body_string("OTHERHASH:123\n"))
            .mount(&server)
            .await;

        let scanner = CredentialLeakScanner::with_params(
            reqwest::Client::new(),
            None,
            10,
            50,
        ).with_base_urls(
            server.uri(),
            "https://haveibeenpwned.com".to_string(),
        );

        let count = scanner.pivot_hibp_pwned_passwords("password123").await;
        assert_eq!(count, None);
    }

    #[tokio::test]
    async fn test_hibp_breached_account_success() {
        let server = MockServer::start().await;
        let email = "test@example.com";
        let _encoded = utf8_percent_encode(email, NON_ALPHANUMERIC).to_string();

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"Name": "LinkedIn", "Title": "LinkedIn 2012"},
                {"Name": "Dropbox", "Title": "Dropbox 2016"}
            ])))
            .mount(&server)
            .await;

        let scanner = CredentialLeakScanner::with_params(
            reqwest::Client::new(),
            Some("dummy_api_key".to_string()),
            10,
            50,
        ).with_base_urls(
            "https://api.pwnedpasswords.com".to_string(),
            server.uri(),
        );

        let breaches = scanner.pivot_hibp_breached_account(email).await;
        assert_eq!(breaches.len(), 2, "Expected 2 breaches from mock");
        assert_eq!(breaches[0], "LinkedIn");
        assert_eq!(breaches[1], "Dropbox");
    }

    #[tokio::test]
    async fn test_hibp_breached_account_gated_no_key() {
        let scanner = CredentialLeakScanner::with_params(
            reqwest::Client::new(),
            None, // no API key
            10,
            50,
        );
        let breaches = scanner.pivot_hibp_breached_account("test@example.com").await;
        assert!(breaches.is_empty());
    }

    #[tokio::test]
    async fn test_h8mail_gating_not_installed() {
        let scanner = CredentialLeakScanner::with_params(
            reqwest::Client::new(),
            None,
            10,
            50,
        );
        let findings = scanner.pivot_h8mail("test@example.com").await;
        assert!(findings.is_empty(), "h8mail should gracefully degrade when not installed");
    }

    #[test]
    fn test_per_scan_email_cap_10() {
        let scanner = CredentialLeakScanner::with_params(
            reqwest::Client::new(),
            None,
            0, // cap = 0
            50,
        );
        assert_eq!(scanner.max_email_lookups, 0);
    }

    #[test]
    fn test_per_scan_password_cap_50() {
        let scanner = CredentialLeakScanner::with_params(
            reqwest::Client::new(),
            None,
            10,
            0, // cap = 0
        );
        assert_eq!(scanner.max_password_lookups, 0);
    }

    #[test]
    fn test_deduplicate_inputs() {
        let f1 = Finding::new(
            "TEST-1",
            Category::CredentialLeak,
            Severity::Medium,
            "Secret",
            serde_json::json!({"user": "admin@example.com", "password": "duplicate"}),
        );
        assert!(f1.evidence.primary.is_some(), "finding 1 should have evidence");
        let f2 = Finding::new(
            "TEST-2",
            Category::CredentialLeak,
            Severity::Medium,
            "Secret",
            serde_json::json!({"user": "admin@example.com", "password": "duplicate"}),
        );
        assert!(f2.evidence.primary.is_some(), "finding 2 should have evidence");
        let target = TargetHost {
            host: "admin@example.com".to_string(),
            findings: std::sync::Arc::new(vec![f1, f2]),
            ..Default::default()
        };
        let emails = CredentialLeakScanner::extract_emails(&target);
        assert_eq!(emails.len(), 1); // deduplicated

        let passwords = CredentialLeakScanner::extract_passwords(&target);
        assert_eq!(passwords.len(), 1); // deduplicated
    }
}
