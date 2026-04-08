use anyhow::{Result, Context};
use rand::Rng;
use rand_distr::{Beta, Distribution};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, AtomicU32, Ordering};
use tracing::{info, warn, debug};

use crate::core::ai_cascade::AdaptiveContext;

// ─────────────────────────────────────────────────────────────────────────────
// HTTP FINGERPRINT PROFILES
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TlsProfile {
    Chrome126,
    Firefox128,
    Safari17,
    Curl,
    Custom(String),
}

impl TlsProfile {
    pub fn label(&self) -> &str {
        match self {
            TlsProfile::Chrome126 => "Chrome/126",
            TlsProfile::Firefox128 => "Firefox/128",
            TlsProfile::Safari17 => "Safari/17",
            TlsProfile::Curl => "curl/8.x",
            TlsProfile::Custom(s) => s.as_str(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpFingerprint {
    pub user_agent: String,
    pub accept_language: String,
    pub accept_encoding: String,
    pub custom_headers: HashMap<String, String>,
    pub tls_profile: TlsProfile,
    /// Jitter between consecutive requests (milliseconds)
    pub request_delay_ms: u64,
}

/// Represents the mutated request configuration returned by the evasion engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MutatedRequest {
    pub fingerprint: Arc<HttpFingerprint>,
    pub strategy: EvasionStrategy,
    /// If true, the caller should rebuild its reqwest::Client with new TLS config
    pub requires_tls_rebuild: bool,
    /// If true, the caller should route through a fresh ephemeral IP
    pub requires_new_ip: bool,
    /// Optional: AI-rewritten payload body
    pub rewritten_body: Option<String>,
    /// Optional: AI-rewritten URL path
    pub rewritten_path: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EvasionStrategy {
    /// Rotate User-Agent + headers (zero-cost, no AI)
    HeaderRotation,
    /// Switch TLS cipher suite profile
    TlsMutation,
    /// Use local AI (Ollama) to rewrite payload
    AiPayloadRewrite,
    /// Route through a fresh DigitalOcean ephemeral IP
    IpRotation,
    /// All strategies exhausted — target is WAF-hardened
    Exhausted,
}

// ─────────────────────────────────────────────────────────────────────────────
// STOCHASTIC EVASION POLICY
// ─────────────────────────────────────────────────────────────────────────────

/// Thompson Sampling based policy for selecting evasion strategies.
/// Uses Bayesian priors (Beta distribution: alpha=success, beta=failure).
pub struct StochasticEvasionPolicy {
    /// strategy index -> (alpha, beta) using AtomicU32 for lock-free updates
    /// Index mapping: 0: HeaderRotation, 1: TlsMutation, 2: AiPayloadRewrite, 3: IpRotation
    priors: [(AtomicU32, AtomicU32); 4],
}

impl StochasticEvasionPolicy {
    pub fn new() -> Self {
        Self {
            priors: [
                (AtomicU32::new(1), AtomicU32::new(1)), // HeaderRotation
                (AtomicU32::new(1), AtomicU32::new(1)), // TlsMutation
                (AtomicU32::new(1), AtomicU32::new(1)), // AiPayloadRewrite
                (AtomicU32::new(1), AtomicU32::new(1)), // IpRotation
            ],
        }
    }

    fn strategy_to_idx(s: EvasionStrategy) -> Option<usize> {
        match s {
            EvasionStrategy::HeaderRotation => Some(0),
            EvasionStrategy::TlsMutation => Some(1),
            EvasionStrategy::AiPayloadRewrite => Some(2),
            EvasionStrategy::IpRotation => Some(3),
            EvasionStrategy::Exhausted => None,
        }
    }

    fn idx_to_strategy(idx: usize) -> EvasionStrategy {
        match idx {
            0 => EvasionStrategy::HeaderRotation,
            1 => EvasionStrategy::TlsMutation,
            2 => EvasionStrategy::AiPayloadRewrite,
            3 => EvasionStrategy::IpRotation,
            _ => EvasionStrategy::HeaderRotation,
        }
    }

    /// Thompson Sampling: Sample from each strategy's Beta distribution and pick the maximum.
    pub fn select_strategy(&self) -> EvasionStrategy {
        let mut rng = rand::thread_rng();
        let mut best_strategy = EvasionStrategy::HeaderRotation;
        let mut max_sample = -1.0;

        for (idx, (alpha_atom, beta_atom)) in self.priors.iter().enumerate() {
            let alpha = alpha_atom.load(Ordering::Relaxed) as f64;
            let beta = beta_atom.load(Ordering::Relaxed) as f64;

            match Beta::new(alpha, beta) {
                Ok(dist) => {
                    let sample = dist.sample(&mut rng);
                    if sample > max_sample {
                        max_sample = sample;
                        best_strategy = Self::idx_to_strategy(idx);
                    }
                }
                Err(_) => continue,
            }
        }
        best_strategy
    }

    /// Bayesian Update: Increment alpha on success, beta on failure.
    pub fn observe_result(&self, strategy: EvasionStrategy, success: bool) {
        if let Some(idx) = Self::strategy_to_idx(strategy) {
            let (alpha, beta) = &self.priors[idx];
            if success {
                alpha.fetch_add(1, Ordering::Relaxed);
            } else {
                beta.fetch_add(1, Ordering::Relaxed);
            }
            debug!("🛡️ WAF-EVASION: Policy update for {:?}: success={}", strategy, success);
        }
    }
}

/// Context about the original request that was blocked.
#[derive(Debug, Clone)]
pub struct RequestContext {
    pub url: String,
    pub method: String,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
    pub status_code: u16,
}

// ─────────────────────────────────────────────────────────────────────────────
// EVASION ATTEMPT HISTORY
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvasionAttempt {
    pub stage: EvasionStrategy,
    pub user_agent_used: String,
    pub tls_profile_used: String,
    pub result_status: u16,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

// ─────────────────────────────────────────────────────────────────────────────
// WAF EVASION ENGINE
// ─────────────────────────────────────────────────────────────────────────────

pub struct WafEvasionEngine {
    /// Pre-built fingerprint profiles (rotated round-robin)
    profiles: Vec<Arc<HttpFingerprint>>,
    /// Current profile index (atomic for lock-free rotation)
    current_idx: AtomicUsize,
    /// Maximum total retries before giving up on a target
    max_retries: u8,
    /// v4: Adaptive AI Engine for payload mutations (LSH cached)
    ai_engine: Option<Arc<crate::core::ai_cascade::OffPathAiEngine>>,
    /// Thompson Sampling Policy
    policy: Arc<StochasticEvasionPolicy>,
}

impl WafEvasionEngine {
    pub fn new(ai_engine: Option<Arc<crate::core::ai_cascade::OffPathAiEngine>>) -> Self {
        Self {
            profiles: Self::build_profile_pool(),
            current_idx: AtomicUsize::new(0),
            max_retries: 12, // Increased for stochastic trials
            ai_engine,
            policy: Arc::new(StochasticEvasionPolicy::new()),
        }
    }

    pub fn with_max_retries(mut self, max: u8) -> Self {
        self.max_retries = max;
        self
    }

    // ─────────────────────────────────────────────────────────────────────
    // CORE: HANDLE A 403 BLOCK
    // ─────────────────────────────────────────────────────────────────────

    /// Main entry point. Reacts to a 403 response and returns a mutated
    /// request configuration based on the escalation stage.
    pub async fn handle_block(
        &self,
        original: &RequestContext,
        adaptive_ctx: &mut AdaptiveContext,
    ) -> Result<Option<MutatedRequest>> {
        adaptive_ctx.block_count += 1;
        adaptive_ctx.last_status_code = Some(original.status_code);
        adaptive_ctx.was_detected = true;

        // NEW: Observe previous failure if this is not the first block
        if adaptive_ctx.block_count > 1 {
            if let Some(ref last_action) = adaptive_ctx.previous_actions.last() {
                // Heuristic: map action string back to strategy for observation
                // In v4, we assume the last action string maps to the strategy used
                let prev_strategy = match last_action.as_str() {
                    "HeaderRotation" => Some(EvasionStrategy::HeaderRotation),
                    "TlsMutation" => Some(EvasionStrategy::TlsMutation),
                    "AiPayloadRewrite" => Some(EvasionStrategy::AiPayloadRewrite),
                    "IpRotation" => Some(EvasionStrategy::IpRotation),
                    _ => None,
                };
                
                if let Some(s) = prev_strategy {
                    debug!("🛡️ WAF-EVASION: Observing failure for previous strategy {:?}", s);
                    self.policy.observe_result(s, false);
                }
            }
        }

        if adaptive_ctx.block_count > self.max_retries as u32 {
            warn!(
                "🛡️ WAF-EVASION: All {} attempts exhausted for {}. Marking as WAF-hardened.",
                self.max_retries, original.url
            );
            return Ok(None);
        }

        // Thompson Sampling selection
        let strategy = self.policy.select_strategy();

        info!(
            "🛡️ WAF-EVASION: Stochastic Choice {:?} (attempt #{}) for {}",
            strategy, adaptive_ctx.block_count, original.url
        );

        match strategy {
            EvasionStrategy::HeaderRotation => self.rotate_fingerprint(original),
            EvasionStrategy::TlsMutation => self.switch_tls_profile(original),
            EvasionStrategy::AiPayloadRewrite => self.ai_rewrite_payload(original, adaptive_ctx).await,
            EvasionStrategy::IpRotation => self.request_new_ip(original),
            EvasionStrategy::Exhausted => Ok(None),
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // STAGE 1: HEADER / USER-AGENT ROTATION
    // ─────────────────────────────────────────────────────────────────────

    fn rotate_fingerprint(&self, _original: &RequestContext) -> Result<Option<MutatedRequest>> {
        let idx = self.current_idx.fetch_add(1, Ordering::Relaxed);
        let profile = &self.profiles[idx % self.profiles.len()];

        info!("🛡️ WAF-EVASION [Stage 1]: Rotating to profile '{}' (UA: {}...)",
            profile.tls_profile.label(),
            &profile.user_agent[..profile.user_agent.len().min(40)]
        );

        Ok(Some(MutatedRequest {
            fingerprint: profile.clone(),
            strategy: EvasionStrategy::HeaderRotation,
            requires_tls_rebuild: false,
            requires_new_ip: false,
            rewritten_body: None,
            rewritten_path: None,
        }))
    }

    // ─────────────────────────────────────────────────────────────────────
    // STAGE 2: TLS PROFILE SWITCH
    // ─────────────────────────────────────────────────────────────────────

    fn switch_tls_profile(&self, _original: &RequestContext) -> Result<Option<MutatedRequest>> {
        let tls_profiles = [TlsProfile::Chrome126, TlsProfile::Firefox128, TlsProfile::Safari17];
        let idx = self.current_idx.fetch_add(1, Ordering::Relaxed);
        let tls = &tls_profiles[idx % tls_profiles.len()];
        let base_profile = &self.profiles[idx % self.profiles.len()];

        let mut fingerprint_data = (**base_profile).clone();
        fingerprint_data.tls_profile = tls.clone();
        let fingerprint = Arc::new(fingerprint_data);

        Ok(Some(MutatedRequest {
            fingerprint,
            strategy: EvasionStrategy::TlsMutation,
            requires_tls_rebuild: true, // Caller must rebuild reqwest::Client
            requires_new_ip: false,
            rewritten_body: None,
            rewritten_path: None,
        }))
    }

    // ─────────────────────────────────────────────────────────────────────
    // STAGE 3: AI PAYLOAD REWRITE (LOCAL ONLY — OLLAMA)
    // ─────────────────────────────────────────────────────────────────────

    async fn ai_rewrite_payload(
        &self,
        original: &RequestContext,
        adaptive_ctx: &AdaptiveContext,
    ) -> Result<Option<MutatedRequest>> {
        let ai_engine = match &self.ai_engine {
            Some(engine) => engine,
            None => {
                warn!("🛡️ WAF-EVASION [Stage 3]: No local AI engine configured. Falling back to Stage 4.");
                return self.request_new_ip(original);
            }
        };

        info!("🛡️ WAF-EVASION [Stage 3]: Checking LSH cache or enqueuing AI rewrite...");

        // Build a synthetic Finding for context
        let finding = crate::models::Finding::new(
            "WAF-BLOCK-REWRITE",
            crate::models::Category::Recon,
            crate::models::Severity::Medium,
            "WAF blocked request, requiring AI rewrite",
            serde_json::json!({
                "body_preview": original.body.as_deref().map(|b| &b[..b.len().min(256)]),
                "previous_attempts": adaptive_ctx.previous_actions,
                "block_count": adaptive_ctx.block_count,
            }),
        );

        let target = crate::models::TargetHost {
            host: url::Url::parse(&original.url)
                .map(|u| u.host_str().unwrap_or("unknown").to_string())
                .unwrap_or_else(|_| "unknown".to_string()),
            ip: None,
            resolved_ip: None,
            status: crate::models::TargetStatus::Scanning,
            target_type: crate::models::TargetType::Web,
            findings: Arc::new(Vec::new()),
            tool_suggestions: Arc::new(Vec::new()),
            tactical_context: Arc::new(serde_json::json!({})),
            extra_data: Arc::new(serde_json::json!({})),
        };

        let payload = original.body.as_deref().unwrap_or("");
        
        // DEBT-03: Use LSH cache for mutations
        if let Some(mutation) = ai_engine.get_mutation_or_enqueue(payload, finding, target).await {
            let idx = self.current_idx.fetch_add(1, Ordering::Relaxed);
            let base = &self.profiles[idx % self.profiles.len()];
            
            let mut fingerprint_data = (**base).clone();
            fingerprint_data.request_delay_ms = rand::thread_rng().gen_range(1000..3000);
            let fingerprint = Arc::new(fingerprint_data);

            Ok(Some(MutatedRequest {
                fingerprint,
                strategy: EvasionStrategy::AiPayloadRewrite,
                requires_tls_rebuild: true,
                requires_new_ip: false,
                rewritten_body: Some(mutation),
                rewritten_path: None,
            }))
        } else {
            // Miss: fallback to Stage 4 while background worker generates the mutation for next time
            warn!("🛡️ WAF-EVASION [Stage 3]: LSH miss. Enqueued background analysis. Falling back to Stage 4.");
            self.request_new_ip(original)
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // STAGE 4: IP ROTATION (REQUEST NEW EPHEMERAL DO NODE)
    // ─────────────────────────────────────────────────────────────────────

    fn request_new_ip(&self, original: &RequestContext) -> Result<Option<MutatedRequest>> {
        info!(
            "🛡️ WAF-EVASION [Stage 4]: Requesting fresh IP via DO ephemeral node for {}",
            original.url
        );

        let idx = self.current_idx.fetch_add(1, Ordering::Relaxed);
        let fingerprint = self.profiles[idx % self.profiles.len()].clone();

        Ok(Some(MutatedRequest {
            fingerprint,
            strategy: EvasionStrategy::IpRotation,
            requires_tls_rebuild: true,
            requires_new_ip: true, // Signal to caller to spin up new DO droplet
            rewritten_body: None,
            rewritten_path: None,
        }))
    }

    // ─────────────────────────────────────────────────────────────────────
    // PROFILE POOL BUILDER
    // ─────────────────────────────────────────────────────────────────────

    fn build_profile_pool() -> Vec<Arc<HttpFingerprint>> {
        let raw = vec![
            // Chrome on Windows 11
            HttpFingerprint {
                user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36".to_string(),
                accept_language: "en-US,en;q=0.9".to_string(),
                accept_encoding: "gzip, deflate, br, zstd".to_string(),
                custom_headers: HashMap::from([
                    ("Sec-CH-UA".to_string(), "\"Chromium\";v=\"126\", \"Not;A=Brand\";v=\"24\", \"Google Chrome\";v=\"126\"".to_string()),
                    ("Sec-CH-UA-Platform".to_string(), "\"Windows\"".to_string()),
                    ("Sec-CH-UA-Mobile".to_string(), "?0".to_string()),
                    ("Sec-Fetch-Dest".to_string(), "document".to_string()),
                    ("Sec-Fetch-Mode".to_string(), "navigate".to_string()),
                    ("Sec-Fetch-Site".to_string(), "none".to_string()),
                    ("Sec-Fetch-User".to_string(), "?1".to_string()),
                    ("Upgrade-Insecure-Requests".to_string(), "1".to_string()),
                ]),
                tls_profile: TlsProfile::Chrome126,
                request_delay_ms: 500,
            },
            // Firefox on Linux
            HttpFingerprint {
                user_agent: "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0".to_string(),
                accept_language: "en-US,en;q=0.5".to_string(),
                accept_encoding: "gzip, deflate, br".to_string(),
                custom_headers: HashMap::from([
                    ("Sec-Fetch-Dest".to_string(), "document".to_string()),
                    ("Sec-Fetch-Mode".to_string(), "navigate".to_string()),
                    ("Sec-Fetch-Site".to_string(), "none".to_string()),
                    ("Sec-Fetch-User".to_string(), "?1".to_string()),
                    ("Upgrade-Insecure-Requests".to_string(), "1".to_string()),
                    ("DNT".to_string(), "1".to_string()),
                ]),
                tls_profile: TlsProfile::Firefox128,
                request_delay_ms: 300,
            },
            // Safari on macOS
            HttpFingerprint {
                user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15".to_string(),
                accept_language: "en-US,en;q=0.9".to_string(),
                accept_encoding: "gzip, deflate, br".to_string(),
                custom_headers: HashMap::from([
                    ("Sec-Fetch-Dest".to_string(), "document".to_string()),
                    ("Sec-Fetch-Mode".to_string(), "navigate".to_string()),
                    ("Sec-Fetch-Site".to_string(), "none".to_string()),
                ]),
                tls_profile: TlsProfile::Safari17,
                request_delay_ms: 700,
            },
            // Chrome on macOS
            HttpFingerprint {
                user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36".to_string(),
                accept_language: "en-GB,en;q=0.9,en-US;q=0.8".to_string(),
                accept_encoding: "gzip, deflate, br, zstd".to_string(),
                custom_headers: HashMap::from([
                    ("Sec-CH-UA".to_string(), "\"Chromium\";v=\"126\", \"Google Chrome\";v=\"126\"".to_string()),
                    ("Sec-CH-UA-Platform".to_string(), "\"macOS\"".to_string()),
                    ("Sec-CH-UA-Mobile".to_string(), "?0".to_string()),
                    ("Upgrade-Insecure-Requests".to_string(), "1".to_string()),
                ]),
                tls_profile: TlsProfile::Chrome126,
                request_delay_ms: 400,
            },
            // Edge on Windows
            HttpFingerprint {
                user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0".to_string(),
                accept_language: "en-US,en;q=0.9".to_string(),
                accept_encoding: "gzip, deflate, br, zstd".to_string(),
                custom_headers: HashMap::from([
                    ("Sec-CH-UA".to_string(), "\"Microsoft Edge\";v=\"126\", \"Chromium\";v=\"126\"".to_string()),
                    ("Sec-CH-UA-Platform".to_string(), "\"Windows\"".to_string()),
                    ("Sec-CH-UA-Mobile".to_string(), "?0".to_string()),
                ]),
                tls_profile: TlsProfile::Chrome126,
                request_delay_ms: 350,
            },
            // Chrome on Android (mobile)
            HttpFingerprint {
                user_agent: "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.72 Mobile Safari/537.36".to_string(),
                accept_language: "en-US,en;q=0.9".to_string(),
                accept_encoding: "gzip, deflate, br".to_string(),
                custom_headers: HashMap::from([
                    ("Sec-CH-UA-Mobile".to_string(), "?1".to_string()),
                    ("Sec-CH-UA-Platform".to_string(), "\"Android\"".to_string()),
                ]),
                tls_profile: TlsProfile::Chrome126,
                request_delay_ms: 800,
            },
            // Firefox on Windows
            HttpFingerprint {
                user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0".to_string(),
                accept_language: "de-DE,de;q=0.9,en;q=0.5".to_string(),
                accept_encoding: "gzip, deflate, br".to_string(),
                custom_headers: HashMap::from([
                    ("DNT".to_string(), "1".to_string()),
                    ("Upgrade-Insecure-Requests".to_string(), "1".to_string()),
                ]),
                tls_profile: TlsProfile::Firefox128,
                request_delay_ms: 450,
            },
            // Googlebot (some WAFs whitelist crawlers)
            HttpFingerprint {
                user_agent: "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)".to_string(),
                accept_language: "*".to_string(),
                accept_encoding: "gzip, deflate".to_string(),
                custom_headers: HashMap::new(),
                tls_profile: TlsProfile::Curl,
                request_delay_ms: 2000,
            },
            // Curl-like minimal
            HttpFingerprint {
                user_agent: "curl/8.7.1".to_string(),
                accept_language: "".to_string(),
                accept_encoding: "gzip".to_string(),
                custom_headers: HashMap::new(),
                tls_profile: TlsProfile::Curl,
                request_delay_ms: 100,
            },
            // Safari on iOS
            HttpFingerprint {
                user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1".to_string(),
                accept_language: "es-419,es;q=0.9".to_string(),
                accept_encoding: "gzip, deflate, br".to_string(),
                custom_headers: HashMap::from([
                    ("Sec-Fetch-Dest".to_string(), "document".to_string()),
                    ("Sec-Fetch-Mode".to_string(), "navigate".to_string()),
                ]),
                tls_profile: TlsProfile::Safari17,
                request_delay_ms: 600,
            },
        ];
        raw.into_iter().map(Arc::new).collect()
    }

    /// Get the number of available fingerprint profiles.
    pub fn profile_count(&self) -> usize {
        self.profiles.len()
    }

    /// Get the current evasion strategy for a given adaptive context.
    /// Note: In v4 this is non-deterministic, this helper returns the LAST tried strategy if available.
    pub fn last_strategy(_adaptive_ctx: &AdaptiveContext) -> EvasionStrategy {
        EvasionStrategy::HeaderRotation // Placeholder
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HELPER: Build reqwest::Client headers from an HttpFingerprint
// ─────────────────────────────────────────────────────────────────────────────

impl HttpFingerprint {
    /// Applies this fingerprint's headers to a reqwest::RequestBuilder.
    pub fn apply_to_headers(&self) -> reqwest::header::HeaderMap {
        let mut headers = reqwest::header::HeaderMap::new();

        if let Ok(v) = reqwest::header::HeaderValue::from_str(&self.user_agent) {
            headers.insert(reqwest::header::USER_AGENT, v);
        }
        if !self.accept_language.is_empty() {
            if let Ok(v) = reqwest::header::HeaderValue::from_str(&self.accept_language) {
                headers.insert(reqwest::header::ACCEPT_LANGUAGE, v);
            }
        }
        if !self.accept_encoding.is_empty() {
            if let Ok(v) = reqwest::header::HeaderValue::from_str(&self.accept_encoding) {
                headers.insert(reqwest::header::ACCEPT_ENCODING, v);
            }
        }

        for (key, value) in &self.custom_headers {
            if let (Ok(k), Ok(v)) = (
                reqwest::header::HeaderName::from_bytes(key.as_bytes()),
                reqwest::header::HeaderValue::from_str(value),
            ) {
                headers.insert(k, v);
            }
        }

        headers
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TESTS
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_request_ctx() -> RequestContext {
        RequestContext {
            url: "https://target.com/api/v1/data".to_string(),
            method: "GET".to_string(),
            headers: HashMap::from([("User-Agent".to_string(), "old-agent".to_string())]),
            body: None,
            status_code: 403,
        }
    }

    #[test]
    fn test_profile_pool_is_populated() {
        let engine = WafEvasionEngine::new(None);
        assert!(engine.profile_count() >= 10, "Profile pool should have at least 10 entries");
    }

    #[test]
    fn test_fingerprint_rotation_cycles_through_profiles() {
        let engine = WafEvasionEngine::new(None);
        let ctx = make_request_ctx();

        let r1 = engine.rotate_fingerprint(&ctx).unwrap().unwrap();
        let r2 = engine.rotate_fingerprint(&ctx).unwrap().unwrap();

        // Consecutive rotations should produce different User-Agents
        assert_ne!(r1.fingerprint.user_agent, r2.fingerprint.user_agent);
        assert!(!r1.requires_tls_rebuild);
        assert!(!r1.requires_new_ip);
    }

    #[test]
    fn test_stochastic_policy_selection() {
        let policy = StochasticEvasionPolicy::new();
        let s = policy.select_strategy();
        // Since all priors are (1,1), it should return one of the 4 valid strategies
        assert!(matches!(s, EvasionStrategy::HeaderRotation | EvasionStrategy::TlsMutation | EvasionStrategy::AiPayloadRewrite | EvasionStrategy::IpRotation));
    }

    #[tokio::test]
    async fn test_max_retries_returns_none() {
        let engine = WafEvasionEngine::new(None).with_max_retries(2);
        let ctx = make_request_ctx();
        let mut adaptive = AdaptiveContext::default();

        // First two should succeed
        let r1 = engine.handle_block(&ctx, &mut adaptive).await.unwrap();
        assert!(r1.is_some());
        let r2 = engine.handle_block(&ctx, &mut adaptive).await.unwrap();
        assert!(r2.is_some());

        // Third should be exhausted (block_count = 3 > max_retries = 2)
        let r3 = engine.handle_block(&ctx, &mut adaptive).await.unwrap();
        assert!(r3.is_none(), "Should return None after max_retries exceeded");
    }

    #[test]
    fn test_tls_profile_switch_requires_rebuild() {
        let engine = WafEvasionEngine::new(None);
        let ctx = make_request_ctx();
        let result = engine.switch_tls_profile(&ctx).unwrap().unwrap();
        assert!(result.requires_tls_rebuild);
        assert!(!result.requires_new_ip);
        assert_eq!(result.strategy, EvasionStrategy::TlsMutation);
    }

    #[test]
    fn test_ip_rotation_requires_new_ip() {
        let engine = WafEvasionEngine::new(None);
        let ctx = make_request_ctx();
        let result = engine.request_new_ip(&ctx).unwrap().unwrap();
        assert!(result.requires_new_ip);
        assert_eq!(result.strategy, EvasionStrategy::IpRotation);
    }

    #[test]
    fn test_fingerprint_apply_to_headers() {
        let profile = &WafEvasionEngine::build_profile_pool()[0]; // Chrome on Windows
        let headers = profile.apply_to_headers();

        assert!(headers.contains_key(reqwest::header::USER_AGENT));
        assert!(headers.contains_key(reqwest::header::ACCEPT_LANGUAGE));
        // Sec-CH-UA from custom_headers
        assert!(headers.contains_key("sec-ch-ua"));
    }
}
