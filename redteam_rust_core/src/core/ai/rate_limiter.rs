use governor::{Quota, RateLimiter};
use governor::state::direct::NotKeyed;
use governor::state::InMemoryState;
use governor::clock::{DefaultClock, Clock};
use std::num::NonZeroU32;
use std::time::Duration;
use dashmap::DashMap;
use crate::core::ai::types::LlmProviderKind;

pub struct ProviderRateLimiter {
    limiters: DashMap<LlmProviderKind, RateLimiter<NotKeyed, InMemoryState, DefaultClock>>,
}

impl ProviderRateLimiter {
    pub fn new() -> Self {
        Self { limiters: DashMap::new() }
    }

    pub fn register(&self, kind: LlmProviderKind, rpm: u32) {
        let quota = Quota::per_minute(NonZeroU32::new(rpm.max(1)).unwrap());
        let limiter = RateLimiter::direct(quota);
        self.limiters.insert(kind, limiter);
    }

    pub fn check(&self, kind: &LlmProviderKind) -> Option<Duration> {
        self.limiters.get(kind).and_then(|entry| {
            entry.check().err().map(|neg| {
                let clock = DefaultClock::default();
                neg.wait_time_from(clock.now())
            })
        })
    }
}

impl Default for ProviderRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}
