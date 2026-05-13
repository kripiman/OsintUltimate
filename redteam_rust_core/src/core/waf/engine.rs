use anyhow::Result;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tracing::{info, warn, debug};

use crate::core::ai::{AdaptiveContext, OffPathAiEngine};
use super::profiles::{HttpFingerprint, MutatedRequest, build_profile_pool};
use super::policy::{StochasticEvasionPolicy, EvasionStrategy};

/// Context about the original request that was blocked.
#[derive(Debug, Clone)]
pub struct RequestContext {
    pub url: String,
    pub method: String,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
    pub status_code: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvasionAttempt {
    pub stage: EvasionStrategy,
    pub user_agent_used: String,
    pub tls_profile_used: String,
    pub result_status: u16,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

pub struct WafEvasionEngine {
    /// Pre-built fingerprint profiles (rotated round-robin)
    profiles: Vec<Arc<HttpFingerprint>>,
    /// Current profile index (atomic for lock-free rotation)
    current_idx: AtomicUsize,
    /// Maximum total retries before giving up on a target
    max_retries: u8,
    /// v4: Adaptive AI Engine for payload mutations (LSH cached)
    ai_engine: Option<Arc<OffPathAiEngine>>,
    /// Thompson Sampling Policy
    policy: Arc<StochasticEvasionPolicy>,
}

impl WafEvasionEngine {
    pub fn new(ai_engine: Option<Arc<OffPathAiEngine>>) -> Self {
        Self {
            profiles: build_profile_pool(),
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
            if let Some(last_action) = adaptive_ctx.previous_actions.last() {
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

    fn switch_tls_profile(&self, _original: &RequestContext) -> Result<Option<MutatedRequest>> {
        use super::profiles::TlsProfile;
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
            requires_tls_rebuild: true,
            requires_new_ip: false,
            rewritten_body: None,
            rewritten_path: None,
        }))
    }

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
            file_path: None,
            user: None,
            findings: Arc::new(Vec::new()),
            tool_suggestions: Arc::new(Vec::new()),
            tactical_context: Arc::new(serde_json::json!({})),
            extra_data: Arc::new(serde_json::json!({})),
            version: 0,
            skip_heavy_scan: false,
            scan_id: None,
            scope_id: String::new(),
        };

        let payload = original.body.as_deref().unwrap_or("");
        
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
            warn!("🛡️ WAF-EVASION [Stage 3]: LSH miss. Enqueued background analysis. Falling back to Stage 4.");
            self.request_new_ip(original)
        }
    }

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
            requires_new_ip: true,
            rewritten_body: None,
            rewritten_path: None,
        }))
    }

    pub fn profile_count(&self) -> usize {
        self.profiles.len()
    }
}
