use std::sync::Arc;
use tokio::sync::mpsc;
use std::hash::{Hash, Hasher};
use crate::models::{Finding, TargetHost};
use super::types::RouteLevel;
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
// OFF-PATH AI ENGINE (Non-blocking)
// ─────────────────────────────────────────────────────────────────────────────

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
                    if let Ok(analysis) = router.analyze(&req.finding, &req.target, None).await {
                        cache.insert_mutation(&req.payload, analysis.summary);
                    }
                });
            }
        });

        engine
    }

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
}
