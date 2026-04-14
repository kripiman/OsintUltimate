use rand_distr::LogNormal;
use std::time::Duration;

#[derive(Clone)]
pub struct JitterSleep {
    dist: LogNormal<f64>,
    min_ms: u64,
    max_ms: u64,
}

impl JitterSleep {
    pub fn for_stealth() -> Self {
        Self {
            dist: LogNormal::new(2.0, 1.0).unwrap(),  // Mean ~7.4s, std ~13s
            min_ms: 500,
            max_ms: 10000,
        }
    }

    pub fn minimal() -> Self {
        Self {
            dist: LogNormal::new(0.5, 0.5).unwrap(),  // Mean ~1.8s
            min_ms: 100,
            max_ms: 2000,
        }
    }

    pub async fn apply(&self) {
        let ms = {
            use rand_distr::Distribution;
            let mut rng = rand::thread_rng();
            let sample = self.dist.sample(&mut rng);
            (sample * 1000.0).clamp(self.min_ms as f64, self.max_ms as f64) as u64
        };
        tokio::time::sleep(Duration::from_millis(ms)).await;
    }
}
