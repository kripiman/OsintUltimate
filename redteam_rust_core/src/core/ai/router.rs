use std::sync::Arc;
use tracing::info;
use thiserror::Error;
use std::hash::{Hash, Hasher};
use std::time::Duration;
use std::sync::atomic::Ordering;
use moka::future::Cache;
use siphasher::sip::SipHasher13;
use once_cell::sync::Lazy;
use anyhow::{Result, anyhow};
use crate::models::{Finding, AIAnalysis, TargetHost};
use crate::plugins::PluginMetadata;
use crate::core::ai::traits::LlmClient;
use super::compressor::ContextCompressor;
use super::token_optimizer::{PROMPT_OPTIMIZER, OptimizationLevel};
use super::types::{RouteLevel, LlmProviderKind, ProviderEntry, AdaptiveContext, CacheMetrics, Posture, CavemanLevel};

const ALL_LEVELS: [RouteLevel; 4] = [RouteLevel::Local, RouteLevel::FreeTier, RouteLevel::Mid, RouteLevel::Premium];

fn iter_levels_upward(from: RouteLevel) -> impl Iterator<Item = RouteLevel> {
    ALL_LEVELS.iter().copied().filter(move |l| *l as i32 >= from as i32)
}

#[derive(Error, Debug)]
pub enum RouterError {
    #[error("API Authentication failed (401/Unauthorized)")]
    Unauthorized,
    #[error("Rate limited by provider (429). Retry after: {retry_after:?}. Daily quota: {daily_quota}")]
    RateLimited { retry_after: Option<Duration>, daily_quota: bool },
    #[error("Provider internal error (500+)")]
    InternalError,
    #[error("Generic analysis failure: {0}")]
    Generic(String),
}

impl RouterError {
    fn from_anyhow(err: &anyhow::Error) -> Self {
        let msg = err.to_string().to_lowercase();
        if msg.contains("401") || msg.contains("unauthorized") || msg.contains("invalid") {
            RouterError::Unauthorized
        } else if msg.contains("429") || msg.contains("rate limit") || msg.contains("too many") {
            let daily_quota = msg.contains("daily quota") || msg.contains("quota exceeded") || msg.contains("quota limit");
            let retry_after = Self::parse_retry_after_from_msg(&msg);
            RouterError::RateLimited { retry_after, daily_quota }
        } else if msg.contains("500") || msg.contains("502") || msg.contains("503") || msg.contains("unreachable") {
            RouterError::InternalError
        } else {
            RouterError::Generic(msg)
        }
    }

    fn parse_retry_after_from_msg(msg: &str) -> Option<Duration> {
        // Look for patterns like "retry after: 30" or "retry-after: 60"
        msg.split(|c: char| !c.is_alphanumeric() && c != ':' && c != '-').find_map(|token| {
            if let Some(idx) = token.find("retry-after:") {
                token[idx + "retry-after:".len()..].trim().parse::<u64>().ok().map(Duration::from_secs)
            } else if let Some(idx) = token.find("retryafter:") {
                token[idx + "retryafter:".len()..].trim().parse::<u64>().ok().map(Duration::from_secs)
            } else {
                None
            }
        })
    }
}

use arc_swap::ArcSwap;

/// Orchestrates multiple LLM clients based on task complexity/severity.
pub struct TieredAIRouter {
    pub providers: ArcSwap<std::collections::HashMap<RouteLevel, Vec<ProviderEntry>>>,
    pub skill_manager: Option<Arc<crate::core::skills::SkillManager>>,
    analysis_cache: Cache<String, AIAnalysis>, // TACTICAL CACHE: Prevents Azure credit bleed
    injection_cache: Cache<String, String>,    // V14.8: Caches skill-injection prompts
    metrics: Arc<CacheMetrics>,
    pub rate_limiter: Option<Arc<super::rate_limiter::ProviderRateLimiter>>,
}

impl Default for TieredAIRouter {
    fn default() -> Self {
        Self::new()
    }
}

impl TieredAIRouter {
    pub fn new() -> Self {
        Self {
            providers: ArcSwap::from_pointee(std::collections::HashMap::new()),
            skill_manager: None,
            analysis_cache: Cache::builder()
                .max_capacity(5000)
                .time_to_live(Duration::from_secs(7200)) // 2h TTL
                .build(),
            injection_cache: Cache::builder()
                .max_capacity(1000)
                .time_to_live(Duration::from_secs(1800)) // 30m TTL for ephemeral skills
                .build(),
            metrics: Arc::new(CacheMetrics::default()),
            rate_limiter: None,
        }
    }

    pub fn with_rate_limiter(mut self, rl: Arc<super::rate_limiter::ProviderRateLimiter>) -> Self {
        self.rate_limiter = Some(rl);
        self
    }

    pub fn with_skills(mut self, sm: Arc<crate::core::skills::SkillManager>) -> Self {
        self.skill_manager = Some(sm);
        self
    }

    pub fn add_provider(&self, level: RouteLevel, kind: LlmProviderKind, priority: u8, client: Arc<dyn LlmClient>) {
        self.providers.rcu(|old| {
            let mut map = old.as_ref().clone();
            let entry = ProviderEntry { kind, priority, client: client.clone() };
            let level_providers = map.entry(level).or_default();
            level_providers.push(entry);
            level_providers.sort_by_key(|p| p.priority);
            Arc::new(map)
        });
    }

    fn calculate_finding_cache_key(finding: &Finding, target: &TargetHost) -> String {
        // RADICAL-FIX: SipHash-1-3 for HashDoS resistance and speed
        static SIPHASH_KEY: Lazy<(u64, u64)> = Lazy::new(|| {
            let mut rng = rand::thread_rng();
            (rand::Rng::gen(&mut rng), rand::Rng::gen(&mut rng))
        });

        let mut hasher = SipHasher13::new_with_keys(SIPHASH_KEY.0, SIPHASH_KEY.1);
        target.host.hash(&mut hasher);
        target.ip.hash(&mut hasher);
        finding.core.id.hash(&mut hasher);
        finding.core.category.hash(&mut hasher);
        
        format!("f:{:x}", hasher.finish())
    }

    /// Note: this method is not instrumented. Use analyze/decide_action for telemetry.
    /// AI-Decision logic is now WAF-aware and OPSEC-aware.
    pub fn classify(&self, finding: &Finding, target: &TargetHost) -> RouteLevel {
        let cvss = finding.enrichment.cvss_score.unwrap_or(0.0);
        let mut level = if cvss >= 8.5 {
            RouteLevel::Premium
        } else if cvss >= 5.0 {
            RouteLevel::Mid
        } else {
            RouteLevel::Local
        };

        // Escalate for sensitive categories (Credentials, Exposed Assets)
        if finding.core.category == crate::models::Category::CredentialLeak || finding.core.category == crate::models::Category::ExposedAsset {
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

        // Source-aware findings prefer Local Code-Models (Tier 0) 
        if let Some(ref evidence) = finding.evidence.primary {
            if evidence.data.get("type").and_then(|v| v.as_str()) == Some("source_aware") {
                return RouteLevel::Local;
            }
        }

        level
    }

    pub async fn analyze(&self, finding: &Finding, target: &TargetHost, attack_context: Option<&str>) -> Result<AIAnalysis> {
        let level = self.classify(finding, target);
        let caveman = if level == RouteLevel::Premium {
            super::types::CavemanLevel::WenyanUltra
        } else {
            super::types::CavemanLevel::default()
        };
        self.analyze_with_level(finding, target, attack_context, level, caveman).await
    }

    pub async fn analyze_with_level(&self, finding: &Finding, target: &TargetHost, attack_context: Option<&str>, target_level: RouteLevel, caveman: super::types::CavemanLevel) -> Result<AIAnalysis> {
        let cache_key = Self::calculate_finding_cache_key(finding, target);
        if let Some(cached) = self.analysis_cache.get(&cache_key) {
            self.metrics.hits.fetch_add(1, Ordering::Relaxed);
            return Ok(cached);
        }

        self.metrics.misses.fetch_add(1, Ordering::Relaxed);
        
        for current_level in iter_levels_upward(target_level) {
            let providers_map = self.providers.load();
            if let Some(providers) = providers_map.get(&current_level) {
                // SKILL INJECTION BRIDGE (ENRICHED)
                let effective_ctx = self.enrich_context_v15(finding, attack_context, current_level, Posture::Ghost, caveman).await;

                for entry in providers {
                    let config = crate::core::ai::traits::InferenceConfig {
                        finding,
                        target,
                        attack_context: effective_ctx.as_deref(),
                        route_level: current_level,
                        caveman,
                    };
                    // LOCAL RATE LIMIT GUARD
                    if let Some(ref rl) = self.rate_limiter {
                        if let Some(wait) = rl.check(&entry.kind) {
                            let capped = wait.min(Duration::from_secs(30));
                            tracing::warn!("TieredRouter: Provider {:?} locally rate limited. Waiting {:?}...", entry.kind, capped);
                            tokio::time::sleep(capped).await;
                            continue;
                        }
                    }

                    match entry.client.analyze(config).await {
                        Ok(analysis) => {
                            match current_level {
                                RouteLevel::Local => crate::utils::telemetry::METRIC_LOCAL_QWEN_TRIAGE.fetch_add(1, Ordering::Relaxed),
                                RouteLevel::FreeTier => crate::utils::telemetry::METRIC_FREETIER_CALLS.fetch_add(1, Ordering::Relaxed),
                                RouteLevel::Mid => crate::utils::telemetry::METRIC_MID_LLM_CALLS.fetch_add(1, Ordering::Relaxed),
                                RouteLevel::Premium => crate::utils::telemetry::METRIC_PREMIUM_LLM_CALLS.fetch_add(1, Ordering::Relaxed),
                            };
                            let mut analysis = analysis;
                            analysis.model = format!("{} (Tiered: {:?}, Provider: {:?})", analysis.model, current_level, entry.kind);
                            self.analysis_cache.insert(cache_key, analysis.clone()).await;
                            return Ok(analysis);
                        }
                        Err(e) => {
                            let router_err = RouterError::from_anyhow(&e);
                            tracing::warn!("TieredRouter: Provider {:?} in {:?} failed ({:?}). Trying next...", entry.kind, current_level, router_err);
                            
                            if let RouterError::RateLimited { retry_after, daily_quota } = &router_err {
                                if *daily_quota {
                                    tracing::error!("🚨 [TieredRouter] Daily quota exhausted for {:?}. Skipping.", entry.kind);
                                }
                                if let Some(d) = retry_after {
                                    let capped = (*d).min(Duration::from_secs(30));
                                    tracing::info!("[TieredRouter] RateLimited on {:?}. Sleeping {:?} before next provider...", entry.kind, capped);
                                    tokio::time::sleep(capped).await;
                                }
                            }
                            
                            if matches!(router_err, RouterError::Unauthorized) {
                                tracing::error!("🚨 [TieredRouter] 401 Unauthorized detectado en {:?}. Activando Failover Bridge.", entry.kind);
                            }
                        }
                    }
                }
            }
        }
        
        Err(anyhow!("All TieredAIRouter providers failed for {}", finding.core.id))
    }

    pub async fn decide_action(
        &self,
        finding: &Finding,
        target: &TargetHost,
        plugins: &[PluginMetadata],
        attack_context: Option<&str>,
        adaptive_context: Option<&AdaptiveContext>,
    ) -> Result<Option<(String, serde_json::Value)>> {
        let target_level = self.classify(finding, target);
        
        for current_level in iter_levels_upward(target_level) {
            let providers_map = self.providers.load();
            if let Some(providers) = providers_map.get(&current_level) {
                let caveman = adaptive_context.map(|c| c.current_caveman).unwrap_or_default();
                let posture = adaptive_context.map(|c| c.posture).unwrap_or(Posture::Ghost);
                
                // SKILL INJECTION FOR DECISION (ENRICHED)
                let effective_ctx = self.enrich_context_v15(finding, attack_context, current_level, posture, caveman).await;

                for entry in providers {
                    let config = crate::core::ai::traits::DecisionConfig {
                        finding,
                        target,
                        plugins,
                        attack_context: effective_ctx.as_deref(),
                        gap: None,
                        adaptive_context,
                        route_level: current_level,
                        caveman,
                    };
                    
                    // LOCAL RATE LIMIT GUARD
                    if let Some(ref rl) = self.rate_limiter {
                        if let Some(wait) = rl.check(&entry.kind) {
                            let capped = wait.min(Duration::from_secs(30));
                            tracing::warn!("TieredRouter: Provider {:?} locally rate limited. Waiting {:?}...", entry.kind, capped);
                            tokio::time::sleep(capped).await;
                            continue;
                        }
                    }

                    match entry.client.decide_action(config).await {
                        Ok(Some((action, context))) => {
                            match current_level {
                                RouteLevel::Local => crate::utils::telemetry::METRIC_LOCAL_QWEN_TRIAGE.fetch_add(1, Ordering::Relaxed),
                                RouteLevel::FreeTier => crate::utils::telemetry::METRIC_FREETIER_CALLS.fetch_add(1, Ordering::Relaxed),
                                RouteLevel::Mid => crate::utils::telemetry::METRIC_MID_LLM_CALLS.fetch_add(1, Ordering::Relaxed),
                                RouteLevel::Premium => crate::utils::telemetry::METRIC_PREMIUM_LLM_CALLS.fetch_add(1, Ordering::Relaxed),
                            };
                            return Ok(Some((action, context)));
                        }
                        Ok(None) => continue,
                        Err(e) => {
                            let router_err = RouterError::from_anyhow(&e);
                            tracing::warn!("TieredRouter: Decision failed with provider {:?} in {:?}: {:?}. Trying next...", entry.kind, current_level, router_err);
                            if let RouterError::RateLimited { retry_after, daily_quota } = &router_err {
                                if *daily_quota {
                                    tracing::error!("🚨 [TieredRouter] Daily quota exhausted for {:?}. Skipping.", entry.kind);
                                }
                                if let Some(d) = retry_after {
                                    let capped = (*d).min(Duration::from_secs(30));
                                    tracing::info!("[TieredRouter] RateLimited on {:?}. Sleeping {:?} before next provider...", entry.kind, capped);
                                    tokio::time::sleep(capped).await;
                                }
                            }
                        }
                    }
                }
            }
        }
        
        Ok(None)
    }

    /// Unified Context Enrichment with Dynamic Budgeting and Token Optimization.
    async fn enrich_context_v15(
        &self,
        finding: &Finding,
        base_ctx: Option<&str>,
        level: RouteLevel,
        posture: Posture,
        caveman: CavemanLevel,
    ) -> Option<String> {
        let mut effective_ctx = base_ctx.map(|s| s.to_string());
        
        if let Some(ref sm) = self.skill_manager {
            let budget = match level {
                RouteLevel::Local => 300,
                RouteLevel::FreeTier => 500,
                RouteLevel::Mid => 800,
                RouteLevel::Premium => 1500,
            };

            // Hardening: Cache skill-injection to prevent redundant heavy optimization
            let cache_key = format!("inj:{:?}:{:?}:{:?}:{}", level, posture, caveman, finding.core.id);
            
            let optimized_injection = if let Some(cached) = self.injection_cache.get(&cache_key) {
                cached
            } else {
                let skills = sm.match_for_context(finding, posture, level, budget).await;
                if !skills.is_empty() {
                    if let Some(injection) = sm.build_injection(&skills, caveman).await {
                        let optimized = if caveman >= CavemanLevel::Ultra {
                            PROMPT_OPTIMIZER.optimize(&injection, OptimizationLevel::Ultra)
                        } else if caveman == CavemanLevel::Lite {
                            PROMPT_OPTIMIZER.optimize(&injection, OptimizationLevel::Lite)
                        } else {
                            PROMPT_OPTIMIZER.optimize(&injection, OptimizationLevel::Full)
                        };
                        self.injection_cache.insert(cache_key.clone(), optimized.clone()).await;
                        optimized
                    } else {
                        return effective_ctx;
                    }
                } else {
                    return effective_ctx;
                }
            };

            info!("🧠 [Router] Inyectando skills técnicos (Tier: {:?}, Cached: {}).", level, self.injection_cache.get(&cache_key).is_some());
            
            effective_ctx = Some(match effective_ctx {
                Some(ctx) => format!("{}\n{}", optimized_injection, ctx),
                None => optimized_injection,
            });
        }
        
        effective_ctx
    }
}
