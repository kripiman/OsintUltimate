use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

pub(super) struct CreditManager {
    daily_budget: u32,
    used_today: Mutex<u32>,
    last_reset: Mutex<u64>,
}

impl CreditManager {
    pub(super) fn new(budget: u32) -> Self {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        Self {
            daily_budget: budget,
            used_today: Mutex::new(0),
            last_reset: Mutex::new(now),
        }
    }

    pub(super) fn can_spend(&self, cost: u32) -> bool {
        let mut used = self.used_today.lock().unwrap();
        let mut last = self.last_reset.lock().unwrap();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();

        if now - *last >= 86400 {
            *used = 0;
            *last = now;
            info!("🛡️ SENTINEL: Daily recon budget reset.");
        }

        if *used + cost <= self.daily_budget {
            *used += cost;
            true
        } else {
            warn!("⚠️ SENTINEL: Daily budget reached ({}/{}). Skipping high-cost API call.", *used, self.daily_budget);
            false
        }
    }
}
