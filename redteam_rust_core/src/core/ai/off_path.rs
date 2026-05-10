use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::mpsc;
use std::hash::{Hash, Hasher};
use crate::models::{Finding, TargetHost};
use super::types::{RouteLevel, CavemanLevel};
use super::router::TieredAIRouter;

pub struct AiMutationRequest {
    pub payload: String,
    pub level: RouteLevel,
    pub finding: Finding,
    pub target: TargetHost,
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
            for (i, v_val) in v.iter_mut().enumerate() {
                if (hash >> i) & 1 == 1 { *v_val += 1; }
                else { *v_val -= 1; }
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
// OFF-PATH AI ENGINE (Non-blocking + Real-time path)
// ─────────────────────────────────────────────────────────────────────────────

pub struct OffPathAiEngine {
    tx: mpsc::Sender<AiMutationRequest>,
    cache: Arc<LshPayloadCache>,
    /// V14.6: Stored for real-time synchronous path (WAF 403 trigger)
    router: Arc<TieredAIRouter>,
    /// V14.6: Metrics for LSH cache efficiency reporting via MCP stats
    pub lsh_cache_hits: AtomicU64,
    pub ai_inference_count: AtomicU64,
}

impl OffPathAiEngine {
    pub fn new(router: Arc<TieredAIRouter>, worker_count: usize) -> Arc<Self> {
        let (tx, mut rx) = mpsc::channel::<AiMutationRequest>(1024);
        let cache = Arc::new(LshPayloadCache::new(8)); // 8 bits threshold

        // P3 fix: clone router for the background worker closure before moving into struct
        let router_for_spawn = router.clone();
        let cache_clone = cache.clone();

        tokio::spawn(async move {
            let semaphore = Arc::new(tokio::sync::Semaphore::new(worker_count));
            while let Some(req) = rx.recv().await {
                let permit = semaphore.clone().acquire_owned().await.unwrap();
                let router = router_for_spawn.clone();
                let cache = cache_clone.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Ok(analysis) = router.analyze(&req.finding, &req.target, None).await {
                        cache.insert_mutation(&req.payload, analysis.summary);
                    }
                });
            }
        });

        Arc::new(Self {
            tx,
            cache,
            router,
            lsh_cache_hits: AtomicU64::new(0),
            ai_inference_count: AtomicU64::new(0),
        })
    }

    /// Background path: enqueue for async AI analysis (training the LSH cache).
    /// Returns cached mutation immediately if available, otherwise enqueues and returns None.
    pub async fn get_mutation_or_enqueue(&self, payload: &str, finding: Finding, target: TargetHost) -> Option<String> {
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

    /// V14.6: Real-time path for WAF 403 triggers.
    /// LSH cache is checked first; on miss, calls Ollama with 2000ms hard timeout.
    /// On timeout or Ollama unavailability, returns None silently (pipeline continues).
    pub async fn get_mutation_realtime(
        &self,
        payload: &str,
        finding: Finding,
        target: TargetHost,
    ) -> Option<String> {
        // 1. LSH cache first — zero latency path
        if let Some(cached) = self.cache.find_similar_mutation(payload) {
            self.lsh_cache_hits.fetch_add(1, Ordering::Relaxed);
            return Some(cached);
        }

        self.ai_inference_count.fetch_add(1, Ordering::Relaxed);

        // 2. Synchronous Ollama inference with 2000ms hard timeout
        let result = tokio::time::timeout(
            Duration::from_millis(2000),
            self.router.analyze_with_level(
                &finding,
                &target,
                Some("WAF evasion: generate a mutated payload variant that evades the current WAF rule"),
                RouteLevel::Local,
                CavemanLevel::Off, // WAF payloads need full English — no compression
            )
        ).await;

        match result {
            Ok(Ok(analysis)) => {
                let mutation = analysis.summary;
                self.cache.insert_mutation(payload, mutation.clone());
                Some(mutation)
            }
            _ => None, // Timeout or Ollama unreachable → silent fallback
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::ai::router::TieredAIRouter;
    use crate::models::{Finding, TargetHost, Category, Severity};
    use std::sync::atomic::Ordering;

    fn dummy_router() -> Arc<TieredAIRouter> {
        Arc::new(TieredAIRouter::new())
    }

    fn dummy_finding() -> Finding {
        Finding::new(
            "TEST_FINDING",
            Category::Vulnerability,
            Severity::Medium,
            "test finding for off-path AI unit test",
            serde_json::json!({}),
        )
    }

    /// LSH cache hit: pre-warm cache, verify realtime returns it without AI inference
    #[tokio::test]
    async fn test_realtime_returns_cached_mutation_immediately() {
        let engine = OffPathAiEngine::new(dummy_router(), 1);

        let payload = "SELECT * FROM users WHERE id=1";
        engine.cache.insert_mutation(payload, "SELECT/**/1/**/FROM/**/users".to_string());

        let result = engine.get_mutation_realtime(
            payload,
            dummy_finding(),
            TargetHost::default(),
        ).await;

        assert!(result.is_some(), "Expected cached mutation to be returned");
        assert_eq!(engine.lsh_cache_hits.load(Ordering::SeqCst), 1, "Expected 1 LSH hit");
        assert_eq!(engine.ai_inference_count.load(Ordering::SeqCst), 0, "Expected 0 AI calls on cache hit");
    }

    /// Cache miss + no providers → get_mutation_realtime returns None, increments ai_inference_count
    #[tokio::test]
    async fn test_realtime_returns_none_on_inference_failure() {
        let engine = OffPathAiEngine::new(dummy_router(), 1); // no providers → Err immediately

        let payload = "'; DROP TABLE sessions;--";
        let result = engine.get_mutation_realtime(
            payload,
            dummy_finding(),
            TargetHost::default(),
        ).await;

        assert!(result.is_none(), "Expected None when inference fails");
        assert_eq!(engine.lsh_cache_hits.load(Ordering::SeqCst), 0, "Expected 0 LSH hits");
        assert_eq!(engine.ai_inference_count.load(Ordering::SeqCst), 1, "Expected 1 AI inference attempt");
    }

    /// Timeout guard: fast-fail path (no providers) completes well under 2500ms
    #[tokio::test]
    async fn test_realtime_completes_within_timeout_on_fast_fail() {
        let engine = OffPathAiEngine::new(dummy_router(), 1);
        let payload = "unique_payload_not_in_cache_xyz987";

        let start = std::time::Instant::now();
        let _ = engine.get_mutation_realtime(payload, dummy_finding(), TargetHost::default()).await;
        let elapsed = start.elapsed();

        assert!(
            elapsed.as_millis() < 2500,
            "get_mutation_realtime fast-fail took {}ms, expected < 2500ms", elapsed.as_millis()
        );
    }
}
