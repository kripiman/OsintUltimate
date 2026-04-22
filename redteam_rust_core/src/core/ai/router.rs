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

#[derive(Error, Debug)]
pub enum RouterError {
    #[error("API Authentication failed (401/Unauthorized)")]
    Unauthorized,
    #[error("Rate limited by provider (429)")]
    RateLimited,
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
            RouterError::RateLimited
        } else if msg.contains("500") || msg.contains("502") || msg.contains("503") || msg.contains("unreachable") {
            RouterError::InternalError
        } else {
            RouterError::Generic(msg)
        }
    }
}

/// Orchestrates multiple LLM clients based on task complexity/severity.
pub struct TieredAIRouter {
    pub providers: std::collections::HashMap<RouteLevel, Vec<ProviderEntry>>,
    pub skill_manager: Option<Arc<crate::core::skills::SkillManager>>,
    analysis_cache: Cache<String, AIAnalysis>, // TACTICAL CACHE: Prevents Azure credit bleed
    metrics: Arc<CacheMetrics>,
}

impl Default for TieredAIRouter {
    fn default() -> Self {
        Self::new()
    }
}

impl TieredAIRouter {
    pub fn new() -> Self {
        Self {
            providers: std::collections::HashMap::new(),
            skill_manager: None,
            analysis_cache: Cache::builder()
                .max_capacity(5000)
                .time_to_live(Duration::from_secs(7200)) // 2h TTL
                .build(),
            metrics: Arc::new(CacheMetrics::default()),
        }
    }

    pub fn with_skills(mut self, sm: Arc<crate::core::skills::SkillManager>) -> Self {
        self.skill_manager = Some(sm);
        self
    }

    pub fn add_provider(&mut self, level: RouteLevel, kind: LlmProviderKind, priority: u8, client: Arc<dyn LlmClient>) {
        let entry = ProviderEntry { kind, priority, client };
        let level_providers = self.providers.entry(level).or_default();
        level_providers.push(entry);
        // Sort by priority (0 = highest)
        level_providers.sort_by_key(|p| p.priority);
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
        finding.id.hash(&mut hasher);
        finding.category.hash(&mut hasher);
        
        format!("f:{:x}", hasher.finish())
    }

    /// V10 HARDENING: AI-Decision logic is now WAF-aware and OPSEC-aware.
    pub fn classify(&self, finding: &Finding, target: &TargetHost) -> RouteLevel {
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

        // NEW V11: Source-aware findings prefer Local Code-Models (Tier 0) 
        // because code snippets are large and local models are often fine-tuned for this.
        if finding.evidence.data.get("type").and_then(|v| v.as_str()) == Some("source_aware") {
            return RouteLevel::Local;
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
        
        for level_val in (target_level as i32)..=2 {
            let current_level = match level_val {
                0 => RouteLevel::Local,
                1 => RouteLevel::Mid,
                2 => RouteLevel::Premium,
                _ => break,
            };

            if let Some(providers) = self.providers.get(&current_level) {
                // V15: SKILL INJECTION BRIDGE (ENRICHED)
                let effective_ctx = self.enrich_context_v15(finding, attack_context, current_level, Posture::Ghost, caveman).await;

                for entry in providers {
                    let config = crate::core::ai::traits::InferenceConfig {
                        finding,
                        target,
                        attack_context: effective_ctx.as_deref(),
                        route_level: current_level,
                        caveman,
                    };
                    match entry.client.analyze(config).await {
                        Ok(analysis) => {
                            let mut analysis = analysis;
                            analysis.model = format!("{} (Tiered: {:?}, Provider: {:?})", analysis.model, current_level, entry.kind);
                            self.analysis_cache.insert(cache_key, analysis.clone()).await;
                            return Ok(analysis);
                        }
                        Err(e) => {
                            let router_err = RouterError::from_anyhow(&e);
                            tracing::warn!("TieredRouter: Provider {:?} in {:?} failed ({:?}). Trying next...", entry.kind, current_level, router_err);
                            
                            if matches!(router_err, RouterError::Unauthorized) {
                                tracing::error!("🚨 [TieredRouter] 401 Unauthorized detectado en {:?}. Activando Failover Bridge.", entry.kind);
                            }
                        }
                    }
                }
            }
        }
        
        Err(anyhow!("All TieredAIRouter providers failed for {}", finding.id))
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
        
        for level_val in (target_level as i32)..=2 {
            let current_level = match level_val {
                0 => RouteLevel::Local,
                1 => RouteLevel::Mid,
                2 => RouteLevel::Premium,
                _ => break,
            };

            if let Some(providers) = self.providers.get(&current_level) {
                let caveman = adaptive_context.map(|c| c.current_caveman).unwrap_or_default();
                let posture = adaptive_context.map(|c| c.posture).unwrap_or(Posture::Ghost);
                
                // V15: SKILL INJECTION FOR DECISION (ENRICHED)
                let effective_ctx = self.enrich_context_v15(finding, attack_context, current_level, posture, caveman).await;

                for entry in providers {
                    let config = crate::core::ai::traits::DecisionConfig {
                        finding,
                        target,
                        plugins: &filtered_plugins,
                        attack_context: effective_ctx.as_deref(),
                        gap: None,
                        adaptive_context,
                        route_level: current_level,
                        caveman,
                    };
                    
                    match entry.client.decide_action(config).await {
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

    /// V15.2: Unified Context Enrichment with Dynamic Budgeting and Token Optimization.
    /// Synergy: Skills selected here directly influence Plugin weighting in PluginRagManager.
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
            // 1. Determine Dynamic Budget based on Tier
            let budget = match level {
                RouteLevel::Local => 300,
                RouteLevel::Mid => 800,
                RouteLevel::Premium => 1500,
            };

            // 2. Match Skills
            let skills = sm.match_for_context(finding, posture, level, budget).await;
            if !skills.is_empty() {
                if let Some(injection) = sm.build_injection(&skills, caveman).await {
                    info!("🧠 [Router] Inyectando {} skills técnicos (Budget: {} tokens, Tier: {:?}).", skills.len(), budget, level);
                    
                    // 3. Apply Token Optimization (Wenyan Ultra) for skill injection
                    // Even if caveman is not Ultra, we want the skills themselves to be as dense as possible
                    let optimized_injection = if caveman >= CavemanLevel::Ultra {
                        PROMPT_OPTIMIZER.optimize(&injection, OptimizationLevel::Ultra)
                    } else if caveman == CavemanLevel::Lite {
                        PROMPT_OPTIMIZER.optimize(&injection, OptimizationLevel::Lite)
                    } else {
                        PROMPT_OPTIMIZER.optimize(&injection, OptimizationLevel::Full)
                    };

                    effective_ctx = Some(match effective_ctx {
                        Some(ctx) => format!("{}\n{}", optimized_injection, ctx),
                        None => optimized_injection,
                    });
                }
            }
        }
        
        effective_ctx
    }
}
