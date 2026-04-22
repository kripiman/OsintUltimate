use rand_distr::{Beta, Distribution};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU32, Ordering};
use tracing::debug;

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

/// Thompson Sampling based policy for selecting evasion strategies.
/// Uses Bayesian priors (Beta distribution: alpha=success, beta=failure).
pub struct StochasticEvasionPolicy {
    /// strategy index -> (alpha, beta) using AtomicU32 for lock-free updates
    /// Index mapping: 0: HeaderRotation, 1: TlsMutation, 2: AiPayloadRewrite, 3: IpRotation
    priors: [(AtomicU32, AtomicU32); 4],
}

impl Default for StochasticEvasionPolicy {
    fn default() -> Self {
        Self::new()
    }
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
