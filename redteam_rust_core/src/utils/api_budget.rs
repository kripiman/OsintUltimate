use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use chrono::{Datelike, Utc, TimeZone};
use tracing::{info, warn};

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum BudgetWindow {
    Daily,
    Monthly,
}

pub(super) struct CreditManager {
    budget: u32,
    window: BudgetWindow,
    used: AtomicU32,
    last_reset: AtomicU64,
}

impl CreditManager {
    pub(super) fn new(budget: u32, window: BudgetWindow) -> Self {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        Self {
            budget,
            window,
            used: AtomicU32::new(0),
            last_reset: AtomicU64::new(now),
        }
    }

    pub(super) fn can_spend(&self, cost: u32) -> bool {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let last = self.last_reset.load(Ordering::Acquire);

        let should_reset = match self.window {
            BudgetWindow::Daily => {
                now.saturating_sub(last) >= 86400
            }
            BudgetWindow::Monthly => {
                if let Some(current_dt) = Utc.timestamp_opt(now as i64, 0).single() {
                    if let Some(last_dt) = Utc.timestamp_opt(last as i64, 0).single() {
                        current_dt.year() > last_dt.year() || current_dt.month() > last_dt.month()
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
        };

        if should_reset {
            self.used.store(0, Ordering::Release);
            self.last_reset.store(now, Ordering::Release);
            let window_str = match self.window {
                BudgetWindow::Daily => "Daily",
                BudgetWindow::Monthly => "Monthly",
            };
            info!("🛡️ SENTINEL: {} recon budget reset.", window_str);
        }

        let mut current_used = self.used.load(Ordering::Acquire);
        loop {
            if current_used + cost <= self.budget {
                match self.used.compare_exchange_weak(
                    current_used,
                    current_used + cost,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => return true,
                    Err(actual) => current_used = actual,
                }
            } else {
                let window_str = match self.window {
                    BudgetWindow::Daily => "Daily",
                    BudgetWindow::Monthly => "Monthly",
                };
                warn!("⚠️ SENTINEL: {} budget reached ({}/{}). Skipping high-cost API call.", window_str, current_used, self.budget);
                return false;
            }
        }
    }
}

use std::collections::HashMap;
use std::sync::OnceLock;

pub struct ApiBudgetRegistry {
    managers: HashMap<String, CreditManager>,
}

static REGISTRY: OnceLock<ApiBudgetRegistry> = OnceLock::new();

impl ApiBudgetRegistry {
    pub fn init(config: &crate::utils::config::Config) {
        let mut managers = HashMap::new();
        managers.insert(
            "netlas".to_string(),
            CreditManager::new(config.netlas_budget, BudgetWindow::Monthly),
        );
        managers.insert(
            "shodan_student".to_string(),
            CreditManager::new(config.shodan_student_budget, BudgetWindow::Monthly),
        );
        managers.insert(
            "shodan_paid".to_string(),
            CreditManager::new(config.shodan_paid_budget, BudgetWindow::Monthly),
        );
        managers.insert(
            "securitytrails".to_string(),
            CreditManager::new(config.securitytrails_budget, BudgetWindow::Monthly),
        );
        managers.insert(
            "criminalip".to_string(),
            CreditManager::new(config.criminalip_budget, BudgetWindow::Monthly),
        );
        managers.insert(
            "zoomeye".to_string(),
            CreditManager::new(config.zoomeye_budget, BudgetWindow::Monthly),
        );
        managers.insert(
            "greynoise".to_string(),
            CreditManager::new(config.greynoise_budget, BudgetWindow::Monthly),
        );
        managers.insert(
            "fofa".to_string(),
            CreditManager::new(config.fofa_budget, BudgetWindow::Monthly),
        );
        managers.insert(
            "chaos".to_string(),
            CreditManager::new(config.chaos_budget, BudgetWindow::Monthly),
        );

        let registry = Self { managers };
        let _ = REGISTRY.set(registry);
    }

    pub fn get() -> &'static Self {
        REGISTRY.get().expect("ApiBudgetRegistry must be initialized")
    }

    pub fn can_spend(&self, source: &str, cost: u32) -> bool {
        if let Some(manager) = self.managers.get(source) {
            let allowed = manager.can_spend(cost);
            if !allowed {
                crate::utils::telemetry::METRIC_BUDGET_SKIPS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            allowed
        } else {
            warn!("⚠️ SENTINEL: Unknown budget source '{}'. Rejecting spend.", source);
            crate::utils::telemetry::METRIC_UNKNOWN_SOURCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            false
        }
    }
}
