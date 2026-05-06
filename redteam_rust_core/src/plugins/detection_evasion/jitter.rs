use crate::utils::common::HumanJitter;
use std::sync::Arc;

pub struct EvasionJitter {
    jitter: Arc<HumanJitter>,
}

impl EvasionJitter {
    pub fn new(min_ms: u64, max_ms: u64) -> Self {
        Self {
            jitter: Arc::new(HumanJitter::new(min_ms, max_ms)),
        }
    }

    pub async fn apply(&self) {
        self.jitter.sleep().await;
    }
}
