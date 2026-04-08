use std::sync::Arc;
use std::hash::{Hash, Hasher};
use std::time::Duration;
use std::sync::atomic::Ordering;
use moka::future::Cache;
use siphasher::sip::SipHasher13;
use once_cell::sync::Lazy;
use anyhow::{Result, anyhow};
use crate::models::{Finding, AIAnalysis, TargetHost};
use crate::plugins::PluginMetadata;
use crate::core::agent::LlmClient;
use super::types::{RouteLevel, LlmProviderKind, ProviderEntry, AdaptiveContext, CacheMetrics};
use super::compressor::ContextCompressor;

/// Orchestrates multiple LLM clients based on task complexity/severity.
pub struct TieredAIRouter {
    pub providers: std::collections::HashMap<RouteLevel, Vec<ProviderEntry>>,
    analysis_cache: Cache<String, AIAnalysis>, // TACTICAL CACHE: Prevents Azure credit bleed
    decision_cache: Cache<String, Option<String>>, // TACTICAL CACHE: Autonomous logic reuse
    metrics: Arc<CacheMetrics>,
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

    pub async fn analyze(&self, finding: &Finding, target: &TargetHost) -> Result<AIAnalysis> {
        let level = self.classify(finding, target);
        self.analyze_with_level(finding, target, level).await
    }

    pub async fn analyze_with_level(&self, finding: &Finding, target: &TargetHost, target_level: RouteLevel) -> Result<AIAnalysis> {
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
        
        Err(anyhow!("All TieredAIRouter providers failed for {}", finding.id))
    }

    pub async fn decide_action(
        &self,
        finding: &Finding,
        target: &TargetHost,
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
