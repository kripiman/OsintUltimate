use crate::models::{Finding, AIAnalysis};
use crate::plugins::PluginMetadata;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::hash::{Hash, Hasher};
use crate::core::agent::LlmClient;
use std::sync::atomic::{AtomicU64, Ordering};
use moka::future::Cache;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RouteLevel {
    Local = 0,   // Ollama / Qwen
    Mid = 1,     // Gemini Flash
    Premium = 2, // Gemini Pro
}

/// ARCH-11: AdaptiveContext tracks the history of attempts to allow the AI
/// to "learn" from failures (e.g., WAF blocks) within a single target scan.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AdaptiveContext {
    pub previous_actions: Vec<String>,
    pub block_count: u32,
    pub last_status_code: Option<u16>,
    pub was_detected: bool,
}

use once_cell::sync::Lazy;
use regex::Regex;

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

static SCRUBBER: Lazy<SecretScrubber> = Lazy::new(SecretScrubber::new);

/// Helper to minify findings and plugins to save tokens.
pub struct ContextCompressor;

impl ContextCompressor {
    pub fn compress_finding(finding: &Finding, route_level: RouteLevel) -> serde_json::Value {
        let mut ev = finding.evidence.data.clone();
        
        // OPSEC 2026: Skip scrubbing for Local (Tier-0) to maximize context
        if route_level != RouteLevel::Local {
            let ev_str = serde_json::to_string(&ev).unwrap_or_default();
            let sanitized_str = SCRUBBER.scrub(&ev_str);
            if let Ok(sanitized_json) = serde_json::from_str(&sanitized_str) {
                ev = sanitized_json;
            }
        }

        // 2. Reduce size for tokens
        if let Some(obj) = ev.as_object_mut() {
            // Truncate large bodies
            if let Some(body) = obj.get_mut("body") {
                if let Some(s) = body.as_str() {
                    if s.len() > 512 {
                        *body = serde_json::json!(format!("{}... [TRUNCATED]", &s[..512]));
                    }
                }
            }
            // Strip noisy headers, keep security/tech ones
            if let Some(headers) = obj.get_mut("headers") {
                if let Some(h_obj) = headers.as_object_mut() {
                    let whitelist = [
                        "server", "x-powered-by", "content-security-policy", 
                        "x-frame-options", "strict-transport-security", "location",
                        "www-authenticate", "x-content-type-options"
                    ];
                    let keys: Vec<String> = h_obj.keys().cloned().collect();
                    for k in keys {
                        if !whitelist.contains(&k.to_lowercase().as_str()) {
                            h_obj.remove(&k);
                        }
                    }
                }
            }
        }

        serde_json::json!({
            "id": finding.id,
            "sev": finding.severity,
            "cat": finding.category,
            "cvss": finding.cvss_score,
            "desc": finding.description.chars().take(200).collect::<String>(),
            "ev": ev,
        })
    }

    pub fn compress_plugins(plugins: &[PluginMetadata]) -> Vec<serde_json::value::Value> {
        plugins.iter().map(|p| {
            serde_json::json!({
                "n": p.name,
                "caps": p.capabilities,
                "lyr": p.layer,
            })
        }).collect()
    }

    /// NEW V10: Compress target host info including tech stack for AI context.
    pub fn compress_target(target: &crate::models::TargetHost) -> serde_json::value::Value {
        let mut tech_stack = Vec::new();
        for finding in &target.findings {
            if finding.category == crate::models::Category::TechnologyStack {
                if let Some(plugins) = finding.evidence.data.get("plugins") {
                    if let Some(obj) = plugins.as_object() {
                        tech_stack.extend(obj.keys().cloned());
                    }
                }
            }
        }

        serde_json::json!({
            "h": target.host,
            "ip": target.ip.as_deref().unwrap_or("unknown"),
            "type": format!("{:?}", target.target_type),
            "tech": tech_stack,
        })
    }
}

/// Orchestrates multiple LLM clients based on task complexity/severity.
pub struct TieredAIRouter {
    pub clients: std::collections::HashMap<RouteLevel, Vec<Arc<dyn LlmClient>>>,
    analysis_cache: Cache<String, AIAnalysis>, // TACTICAL CACHE: Prevents Azure credit bleed
    decision_cache: Cache<String, Option<String>>, // TACTICAL CACHE: Autonomous logic reuse
    metrics: Arc<CacheMetrics>,
}

#[derive(Default)]
pub struct CacheMetrics {
    hits: AtomicU64,
    misses: AtomicU64,
}

impl TieredAIRouter {
    pub fn new() -> Self {
        Self {
            clients: std::collections::HashMap::new(),
            analysis_cache: Cache::builder()
                .max_capacity(5000)
                .time_to_live(Duration::from_secs(7200)) // 2h TTL
                .build(),
            decision_cache: Cache::builder()
                .max_capacity(1000)
                .time_to_live(Duration::from_secs(1800)) // 30m TTL
                .build(),
            metrics: Arc::new(CacheMetrics::default()),
        }
    }

    pub fn add_client(&mut self, level: RouteLevel, client: Arc<dyn LlmClient>) {
        self.clients.entry(level).or_default().push(client);
    }

    fn calculate_finding_cache_key(finding: &Finding, target: &crate::models::TargetHost) -> String {
        // RADICAL-FIX: Deterministic key using stable fields to avoid JSON serialization jitter
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        target.host.hash(&mut hasher);
        target.ip.hash(&mut hasher);
        finding.id.hash(&mut hasher);
        finding.category.hash(&mut hasher);
        finding.description.hash(&mut hasher);
        // We hash the raw evidence pointer or a subset for speed
        format!("f:{:x}", hasher.finish())
    }

    /// V10 HARDENING: AI-Decision logic is now WAF-aware and OPSEC-aware.
    pub fn classify(&self, finding: &Finding, target: &crate::models::TargetHost) -> RouteLevel {
        let cvss = finding.cvss_score.unwrap_or(0.0);
        let mut level = if cvss >= 8.5 {
            RouteLevel::Premium
        } else if cvss >= 5.0 {
            RouteLevel::Mid
        } else {
            RouteLevel::Local
        };

        // Escalate for sensitive categories (Credentials, Exposed Assets)
        if finding.category == crate::models::Category::CredentialLeak || finding.category == crate::models::Category::ExposedAsset {
            level = level.max(RouteLevel::Mid);
        }

        // Detect WAF/Security tech using ContextCompressor logic
        let target_ctx = ContextCompressor::compress_target(target);
        if let Some(tech) = target_ctx.get("tech").and_then(|t| t.as_array()) {
            let waf_tech = ["cloudflare", "incapsula", "akamai", "f5", "barracuda", "sucuri"];
            for t in tech {
                if let Some(name) = t.as_str() {
                    if waf_tech.iter().any(|&w| name.to_lowercase().contains(w)) {
                         level = level.max(RouteLevel::Mid);
                    }
                }
            }
        }

        level
    }

    pub async fn analyze(&self, finding: &Finding, target: &crate::models::TargetHost) -> Result<AIAnalysis> {
        let cache_key = Self::calculate_finding_cache_key(finding, target);
        if let Some(cached) = self.analysis_cache.get(&cache_key) {
            self.metrics.hits.fetch_add(1, Ordering::Relaxed);
            return Ok(cached);
        }

        self.metrics.misses.fetch_add(1, Ordering::Relaxed);
        let target_level = self.classify(finding, target);
        
        for level_val in (target_level as i32)..=2 {
            let current_level = match level_val {
                0 => RouteLevel::Local,
                1 => RouteLevel::Mid,
                2 => RouteLevel::Premium,
                _ => break,
            };

            if let Some(clients) = self.clients.get(&current_level) {
                for client in clients {
                    match client.analyze(finding, target, current_level).await {
                        Ok(analysis) => {
                            let mut analysis = analysis;
                            analysis.model = format!("{} (Tiered: {:?})", analysis.model, current_level);
                            self.analysis_cache.insert(cache_key, analysis.clone()).await;
                            return Ok(analysis);
                        }
                        Err(e) => {
                            tracing::warn!("TieredRouter: Model in {:?} failed: {}. Escalating...", current_level, e);
                        }
                    }
                }
            }
        }
        
        Err(anyhow::anyhow!("All TieredAIRouter attempts failed for {}", finding.id))
    }

    pub async fn decide_action(
        &self,
        finding: &Finding,
        target: &crate::models::TargetHost,
        plugins: &[PluginMetadata],
        adaptive_context: Option<&AdaptiveContext>,
    ) -> Result<Option<(String, serde_json::Value)>> {
        let target_level = self.classify(finding, target);
        
        for level_val in (target_level as i32)..=2 {
            let current_level = match level_val {
                0 => RouteLevel::Local,
                1 => RouteLevel::Mid,
                2 => RouteLevel::Premium,
                _ => break,
            };

            if let Some(clients) = self.clients.get(&current_level) {
                for client in clients {
                    match client.decide_action(finding, target, plugins, None, adaptive_context, current_level).await {
                        Ok(Some((action, context))) => {
                            return Ok(Some((action, context)));
                        }
                        Ok(None) => continue,
                        Err(e) => {
                           tracing::warn!("TieredRouter: Decision failed in {:?}: {}. Escalating...", current_level, e);
                        }
                    }
                }
            }
        }
        
        Ok(None)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Category, Severity, Evidence};
    use serde_json::json;

    fn mock_finding(ev: serde_json::Value) -> Finding {
        Finding {
            id: "test-f".to_string(),
            title: "Test".to_string(),
            description: "Test".to_string(),
            severity: Severity::High,
            category: Category::Vulnerability,
            cvss_score: Some(8.0),
            evidence: Evidence { data: ev },
            ..Default::default()
        }
    }

    #[test]
    fn test_secret_scrubbing_patterns() {
        let scrubber = SecretScrubber::new();
        
        // AWS
        assert_eq!(scrubber.scrub("AKIA1234567890ABCDEF"), "[AWS_ACCESS_KEY]");
        
        // DB Connections (2026 format)
        assert_eq!(
            scrubber.scrub("postgresql://admin:SecretPass123@10.0.5.21:5432/prod"),
            "postgresql://admin:[REDACTED_PASSWORD]@[REDACTED_IP]:5432/prod"
        );

        // JWT
        assert_eq!(scrubber.scrub("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig"), "[JWT_TOKEN]");

        // Internal IPs
        assert_eq!(scrubber.scrub("192.168.1.15"), "[INTERNAL_IP]");
        assert_eq!(scrubber.scrub("8.8.8.8"), "8.8.8.8"); // Public IP stays
    }

    #[test]
    fn test_tier0_exemption() {
        let raw_ev = json!({ "key": "AKIA1234567890ABCDEF", "host": "10.0.0.5" });
        let finding = mock_finding(raw_ev.clone());

        // Tier 0 -> No scrubbing
        let compressed_local = ContextCompressor::compress_finding(&finding, RouteLevel::Local);
        assert_eq!(compressed_local["ev"]["key"], "AKIA1234567890ABCDEF");

        // Tier 1 -> Scrubbing applied
        let compressed_mid = ContextCompressor::compress_finding(&finding, RouteLevel::Mid);
        assert_eq!(compressed_mid["ev"]["key"], "[AWS_ACCESS_KEY]");
    }
}
