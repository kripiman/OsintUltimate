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
use siphasher::sip::SipHasher13;
use tokio::sync::mpsc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RouteLevel {
    Local = 0,   // Ollama / Qwen
    Mid = 1,     // Gemini Flash / GPT-4o-mini
    Premium = 2, // Gemini Pro / GPT-4o / Claude 3.5
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LlmProviderKind {
    Local,
    Gemini,
    Anthropic,
    OpenAI,
    AzureOpenAI,
}

pub struct ProviderEntry {
    pub kind: LlmProviderKind,
    pub priority: u8, // 0 is highest
    pub client: Arc<dyn LlmClient>,
}

/// ARCH-11: AdaptiveContext tracks the history of attempts to allow the AI
/// to "learn" from failures (e.g., WAF blocks) within a single target scan.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AdaptiveContext {
    pub previous_actions: Vec<String>,
    pub block_count: u32,
    pub last_status_code: Option<u16>,
    pub was_detected: bool,
    /// WAF evasion stage tracker (0=header, 1=tls, 2=ai, 3=ip, 4=exhausted)
    pub evasion_stage: u8,
    /// URL that triggered the last WAF block
    pub last_blocked_url: Option<String>,
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
    pub providers: std::collections::HashMap<RouteLevel, Vec<ProviderEntry>>,
    analysis_cache: Cache<String, AIAnalysis>, // TACTICAL CACHE: Prevents Azure credit bleed
    decision_cache: Cache<String, Option<String>>, // TACTICAL CACHE: Autonomous logic reuse
    metrics: Arc<CacheMetrics>,
}

#[derive(Default)]
pub struct CacheMetrics {
    hits: AtomicU64,
    misses: AtomicU64,
}

// ─────────────────────────────────────────────────────────────────────────────
// LSH PAYLOAD CACHING (Locality-Sensitive Hashing)
// ─────────────────────────────────────────────────────────────────────────────

pub struct LshPayloadCache {
    /// SimHash (64-bit) -> List of successful mutations
    signatures: dashmap::DashMap<u64, Vec<String>>,
    hamming_threshold: u32,
}

impl LshPayloadCache {
    pub fn new(threshold: u32) -> Self {
        Self {
            signatures: dashmap::DashMap::new(),
            hamming_threshold: threshold,
        }
    }

    /// SimHash implementation: TF of 3-grams
    pub fn simhash_payload(payload: &str) -> u64 {
        let mut v = [0i64; 64];
        for ngram in payload.as_bytes().windows(3) {
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            ngram.hash(&mut hasher);
            let hash = hasher.finish();
            for i in 0..64 {
                if (hash >> i) & 1 == 1 { v[i] += 1; }
                else { v[i] -= 1; }
            }
        }
        v.iter().enumerate().fold(0u64, |acc, (i, &val)| {
            if val > 0 { acc | (1 << i) } else { acc }
        })
    }

    pub fn hamming_distance(a: u64, b: u64) -> u32 {
        (a ^ b).count_ones()
    }

    pub fn find_similar_mutation(&self, payload: &str) -> Option<String> {
        let sig = Self::simhash_payload(payload);
        for entry in self.signatures.iter() {
            if Self::hamming_distance(sig, *entry.key()) <= self.hamming_threshold {
                let mutations = entry.value();
                if !mutations.is_empty() {
                    let idx = rand::random::<usize>() % mutations.len();
                    return Some(mutations[idx].clone());
                }
            }
        }
        None
    }

    pub fn insert_mutation(&self, payload: &str, mutation: String) {
        let sig = Self::simhash_payload(payload);
        self.signatures.entry(sig).or_default().push(mutation);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OFF-PATH AI ENGINE (Non-blocking)
// ─────────────────────────────────────────────────────────────────────────────

pub struct AiMutationRequest {
    pub payload: String,
    pub level: RouteLevel,
    pub finding: Finding,
    pub target: crate::models::TargetHost,
}

pub struct OffPathAiEngine {
    tx: mpsc::Sender<AiMutationRequest>,
    cache: Arc<LshPayloadCache>,
}

impl OffPathAiEngine {
    pub fn new(router: Arc<TieredAIRouter>, worker_count: usize) -> Arc<Self> {
        let (tx, mut rx) = mpsc::channel::<AiMutationRequest>(1024);
        let cache = Arc::new(LshPayloadCache::new(8)); // 8 bits threshold
        let engine = Arc::new(Self { tx, cache: cache.clone() });

        let cache_clone = cache.clone();
        tokio::spawn(async move {
            let semaphore = Arc::new(tokio::sync::Semaphore::new(worker_count));
            while let Some(req) = rx.recv().await {
                let permit = semaphore.clone().acquire_owned().await.unwrap();
                let router = router.clone();
                let cache = cache_clone.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Ok(analysis) = router.analyze(&req.finding, &req.target).await {
                        cache.insert_mutation(&req.payload, analysis.summary);
                    }
                });
            }
        });

        engine
    }

    pub async fn get_mutation_or_enqueue(&self, payload: &str, finding: Finding, target: crate::models::TargetHost) -> Option<String> {
        if let Some(cached) = self.cache.find_similar_mutation(payload) {
            return Some(cached);
        }

        // Miss: Enqueue for background analysis
        let _ = self.tx.try_send(AiMutationRequest {
            payload: payload.to_string(),
            level: RouteLevel::Local,
            finding,
            target,
        });
        
        None // Fallback to immediate non-AI strategy
    }
}

impl TieredAIRouter {
    pub fn new() -> Self {
        Self {
            providers: std::collections::HashMap::new(),
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

    pub fn add_provider(&mut self, level: RouteLevel, kind: LlmProviderKind, priority: u8, client: Arc<dyn LlmClient>) {
        let entry = ProviderEntry { kind, priority, client };
        let level_providers = self.providers.entry(level).or_default();
        level_providers.push(entry);
        // Sort by priority (0 = highest)
        level_providers.sort_by_key(|p| p.priority);
    }

    fn calculate_finding_cache_key(finding: &Finding, target: &crate::models::TargetHost) -> String {
        // RADICAL-FIX: SipHash-1-3 for HashDoS resistance and speed
        static SIPHASH_KEY: Lazy<(u64, u64)> = Lazy::new(|| {
            let mut rng = rand::thread_rng();
            (rand::Rng::gen(&mut rng), rand::Rng::gen(&mut rng))
        });

        let mut hasher = SipHasher13::new_with_keys(SIPHASH_KEY.0, SIPHASH_KEY.1);
        target.host.hash(&mut hasher);
        target.ip.hash(&mut hasher);
        finding.id.hash(&mut hasher);
        finding.category.hash(&mut hasher);
        
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

            if let Some(providers) = self.providers.get(&current_level) {
                for entry in providers {
                    match entry.client.analyze(finding, target, current_level).await {
                        Ok(analysis) => {
                            let mut analysis = analysis;
                            analysis.model = format!("{} (Tiered: {:?}, Provider: {:?})", analysis.model, current_level, entry.kind);
                            self.analysis_cache.insert(cache_key, analysis.clone()).await;
                            return Ok(analysis);
                        }
                        Err(e) => {
                            tracing::warn!("TieredRouter: Provider {:?} in {:?} failed: {}. Trying next...", entry.kind, current_level, e);
                        }
                    }
                }
            }
        }
        
        Err(anyhow::anyhow!("All TieredAIRouter providers failed for {}", finding.id))
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

            if let Some(providers) = self.providers.get(&current_level) {
                for entry in providers {
                    match entry.client.decide_action(finding, target, plugins, None, adaptive_context, current_level).await {
                        Ok(Some((action, context))) => {
                            return Ok(Some((action, context)));
                        }
                        Ok(None) => continue,
                        Err(e) => {
                           tracing::warn!("TieredRouter: Decision failed with provider {:?} in {:?}: {}. Trying next...", entry.kind, current_level, e);
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
        let mut f = Finding::new("test-f", Category::Vulnerability, Severity::High, "Test", ev);
        f.cvss_score = Some(8.0);
        f
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

    #[tokio::test]
    async fn test_priority_routing_logic() -> Result<()> {
        let mut router = TieredAIRouter::new();
        
        struct MockClient { fail: bool, name: String }
        #[async_trait::async_trait]
        impl LlmClient for MockClient {
            async fn analyze(&self, _: &Finding, _: &crate::models::TargetHost, _: RouteLevel) -> Result<AIAnalysis> {
                if self.fail { Err(anyhow::anyhow!("fail")) }
                else { Ok(AIAnalysis { 
                    summary: "ok".into(), impact: "".into(), stealth_notes: "".into(), 
                    risk_score: 1, confidence: 1.0, mitre_attack: None, 
                    remediation: "".into(), model: self.name.clone() 
                }) }
            }
            async fn decide_action(&self, _: &Finding, _: &crate::models::TargetHost, _: &[crate::plugins::PluginMetadata], _: Option<&crate::core::agent::CapabilityGap>, _: Option<&AdaptiveContext>, _: RouteLevel) -> Result<Option<(String, serde_json::Value)>> {
                Ok(None)
            }
        }

        // Add 3 providers to Local level
        // P0: Fails
        router.add_provider(RouteLevel::Local, LlmProviderKind::Local, 0, Arc::new(MockClient { fail: true, name: "P0".into() }));
        // P1: Succeeds
        router.add_provider(RouteLevel::Local, LlmProviderKind::Local, 1, Arc::new(MockClient { fail: false, name: "P1".into() }));
        // P2: Succeeds (but shouldn't be reached)
        router.add_provider(RouteLevel::Local, LlmProviderKind::Local, 2, Arc::new(MockClient { fail: false, name: "P2".into() }));

        let finding = mock_finding(json!({}));
        let target = crate::models::TargetHost {
            host: "test".into(), ip: None, status: crate::models::TargetStatus::Pending,
            target_type: crate::models::TargetType::Host, findings: vec![],
            tool_suggestions: vec![], tactical_context: json!({}), extra_data: json!({}),
        };

        let res = router.analyze(&finding, &target).await?;
        // Should contain P1 because P0 failed. Analyze format: model (Tiered: level, Provider: kind)
        assert!(res.model.contains("P1"));
        assert!(!res.model.contains("P0"));
        assert!(!res.model.contains("P2"));

        Ok(())
    }

    #[tokio::test]
    async fn test_tier_escalation_logic() -> Result<()> {
        let mut router = TieredAIRouter::new();
        
        struct MockClient { fail: bool, name: String }
        #[async_trait::async_trait]
        impl LlmClient for MockClient {
            async fn analyze(&self, _: &Finding, _: &crate::models::TargetHost, _: RouteLevel) -> Result<AIAnalysis> {
                if self.fail { Err(anyhow::anyhow!("fail")) }
                else { Ok(AIAnalysis { 
                    summary: "ok".into(), impact: "".into(), stealth_notes: "".into(), 
                    risk_score: 1, confidence: 1.0, mitre_attack: None, 
                    remediation: "".into(), model: self.name.clone() 
                }) }
            }
            async fn decide_action(&self, _: &Finding, _: &crate::models::TargetHost, _: &[crate::plugins::PluginMetadata], _: Option<&crate::core::agent::CapabilityGap>, _: Option<&AdaptiveContext>, _: RouteLevel) -> Result<Option<(String, serde_json::Value)>> {
                Ok(None)
            }
        }

        // Local level: all fail
        router.add_provider(RouteLevel::Local, LlmProviderKind::Local, 0, Arc::new(MockClient { fail: true, name: "L0".into() }));
        // Mid level: succeeds
        router.add_provider(RouteLevel::Mid, LlmProviderKind::Gemini, 0, Arc::new(MockClient { fail: false, name: "M0".into() }));

        let finding = mock_finding(json!({}));
        let target = crate::models::TargetHost {
            host: "test".into(), ip: None, status: crate::models::TargetStatus::Pending,
            target_type: crate::models::TargetType::Host, findings: vec![],
            tool_suggestions: vec![], tactical_context: json!({}), extra_data: json!({}),
        };

        let res = router.analyze(&finding, &target).await?;
        assert!(res.model.contains("M0"));
        Ok(())
    }
}
