use tracing::warn;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

#[derive(Debug, Default)]
pub struct TokenBudget {
    pub prompt_tokens: AtomicU32,
    pub completion_tokens: AtomicU32,
    pub total_tokens: AtomicU32,
    pub reserved_tokens: AtomicU32,
    pub max_tokens: u32,
    pub max_per_agent: u32,
    pub priority_boost: AtomicU32, // Reserved for high-priority tasks
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskPriority {
    High, // Planner
    Normal, // Exploiter
    Low, // Scout/Reporter
}

impl TokenBudget {
    pub fn new(max: u32) -> Self {
        let safe_max = if max == 0 { 50_000 } else { max };
        Self {
            max_tokens: safe_max,
            max_per_agent: safe_max / 2, // Default to 50% of budget per agent
            ..Default::default()
        }
    }

    pub fn with_max_per_agent(mut self, max_per_agent: u32) -> Self {
        self.max_per_agent = max_per_agent;
        self
    }

    pub fn add_usage(&self, usage: &crate::models::findings::TokenUsage) {
        self.prompt_tokens.fetch_add(usage.prompt_tokens, Ordering::Relaxed);
        self.completion_tokens.fetch_add(usage.completion_tokens, Ordering::Relaxed);
        self.total_tokens.fetch_add(usage.total_tokens, Ordering::Relaxed);
    }

    /// V12 HARDENING: Race-condition safe reservation using atomic compare_exchange.
    /// Added overflow protection and strict threshold validation.
    pub fn reserve_tokens(&self, amount: u32, priority: TaskPriority) -> bool {
        let mut current_reserved = self.reserved_tokens.load(Ordering::SeqCst);
        loop {
            let total = self.total_tokens.load(Ordering::SeqCst);
            
            // V13 HARDENING: Priority-based admission control with overflow check.
            // Professional safety: Low-priority tasks are throttled earlier to reserve space for critical analysis.
            let threshold = match priority {
                TaskPriority::High => self.max_tokens,
                TaskPriority::Normal => (self.max_tokens as f64 * 0.90) as u32,
                TaskPriority::Low => (self.max_tokens as f64 * 0.75) as u32,
            };

            // Safe overflow check: total + current_reserved + amount
            let projected = total.checked_add(current_reserved)
                .and_then(|sum| sum.checked_add(amount));

            match projected {
                Some(p) if p <= threshold => {
                    match self.reserved_tokens.compare_exchange_weak(
                        current_reserved,
                        current_reserved + amount,
                        Ordering::SeqCst,
                        Ordering::SeqCst,
                    ) {
                        Ok(_) => return true,
                        Err(new_val) => current_reserved = new_val,
                    }
                }
                _ => return false, // Overflow or over threshold
            }
        }
    }

    pub fn release_reservation(&self, amount: u32) {
        self.reserved_tokens.fetch_sub(amount, Ordering::SeqCst);
    }

    pub fn commit_usage(&self, actual: u32, reserved: u32) {
        self.total_tokens.fetch_add(actual, Ordering::SeqCst);
        self.reserved_tokens.fetch_sub(reserved, Ordering::SeqCst);
    }

    pub fn is_exhausted(&self) -> bool {
        (self.total_tokens.load(Ordering::SeqCst) + self.reserved_tokens.load(Ordering::SeqCst)) >= self.max_tokens
    }

    pub fn current_total(&self) -> u32 {
        self.total_tokens.load(Ordering::Relaxed)
    }

    pub fn current_effective_total(&self) -> u32 {
        self.total_tokens.load(Ordering::Relaxed) + self.reserved_tokens.load(Ordering::Relaxed)
    }
}

/// V12 HARDENING: RAII Guard to ensure tokens are released even if an agent panics.
pub struct TokenGuard {
    pub(crate) budget: Arc<TokenBudget>,
    pub(crate) amount: u32,
    pub(crate) active: bool,
}

impl TokenGuard {
    pub fn new(budget: Arc<TokenBudget>, amount: u32, priority: TaskPriority) -> Option<Self> {
        // V13 HARDENING: Enforce per-agent limits
        let safe_amount = if amount > budget.max_per_agent {
            warn!("💸 SWARM: Requested tokens ({}) exceeds per-agent limit ({}). Capping.", amount, budget.max_per_agent);
            budget.max_per_agent
        } else {
            amount
        };

        if budget.reserve_tokens(safe_amount, priority) {
            Some(Self { budget, amount: safe_amount, active: true })
        } else {
            None
        }
    }

    pub fn commit(mut self, actual: u32) {
        self.budget.commit_usage(actual, self.amount);
        self.active = false;
    }
}

impl Drop for TokenGuard {
    fn drop(&mut self) {
        if self.active {
            warn!("💸 SWARM: TokenGuard dropped without commitment. Releasing {} reserved tokens.", self.amount);
            self.budget.release_reservation(self.amount);
        }
    }
}
