use rand_distr::{LogNormal, Distribution};
use tokio::time::{sleep, Duration};
 // V9 FIX (MEDIUM-002): std::sync::RwLock for brief RAM-only blacklist access

pub struct HumanJitter {
    min_delay_ms: f64, // Changed to float for LogNormal calc
    max_delay_ms: f64,
    dist: LogNormal<f64>,
}

impl HumanJitter {
    pub fn new(min_delay_ms: u64, max_delay_ms: u64) -> Self {
        // LogNormal params: mean=0.5, std_dev=0.8 (simulating human reaction)
        let dist = LogNormal::new(0.5, 0.8).unwrap();
        Self {
            min_delay_ms: min_delay_ms as f64,
            max_delay_ms: max_delay_ms as f64,
            dist,
        }
    }

    pub async fn sleep(&self) {
        let base_delay = self.dist.sample(&mut rand::thread_rng()) * 1000.0; // Scale factor
        let delay = base_delay.clamp(self.min_delay_ms, self.max_delay_ms);
        sleep(Duration::from_millis(delay as u64)).await;
    }
}

// ProxyManager moved to utils::proxy
// Stealth: Realistic Browser User-Agents
const REALISTIC_USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0",
];

pub fn get_random_user_agent() -> &'static str {
    use rand::seq::SliceRandom;
    let mut rng = rand::thread_rng();
    REALISTIC_USER_AGENTS.choose(&mut rng).unwrap_or(&REALISTIC_USER_AGENTS[0])
}

// P1 FIX: Check if we are running as root (simplest proxy for CAP_NET_RAW capability check)
pub fn check_cap_net_raw() -> bool {
    #[cfg(unix)]
    {
        rustix::process::geteuid().is_root()
    }
    #[cfg(not(unix))]
    {
        // On non-Unix, assume true and let nmap handle permission errors
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_jitter_range() {
        let jitter = HumanJitter::new(10, 20);
        // We can't easily test duration without mocking time or statistical analysis.
        // But we can ensure it doesn't panic.
        jitter.sleep().await;
        // Pass
    }
}
