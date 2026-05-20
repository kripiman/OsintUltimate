use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use chrono::{Datelike, Utc, TimeZone};
use tracing::{info, warn};
use std::collections::HashMap;
use std::sync::OnceLock;

pub static METRIC_BUDGET_SKIPS: AtomicU64 = AtomicU64::new(0);
pub static METRIC_UNKNOWN_SOURCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum BudgetWindow {
    Daily,
    Monthly,
}

impl BudgetWindow {
    fn suffix(&self) -> String {
        match self {
            BudgetWindow::Daily => Utc::now().format("%Y-%m-%d").to_string(),
            BudgetWindow::Monthly => Utc::now().format("%Y-%m").to_string(),
        }
    }
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

    pub(super) fn can_spend_mem(&self, cost: u32) -> bool {
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

    pub(super) async fn can_spend_db(&self, pool: &sqlx::PgPool, source: &str, cost: u32) -> bool {
        let suffix = self.window.suffix();
        let key = format!("budget:{}:{}", source, suffix);

        // Ensure row exists
        let _ = sqlx::query(
            "INSERT INTO mcp_stats (stat_key, stat_value) VALUES ($1, 0) ON CONFLICT (stat_key) DO NOTHING"
        )
        .bind(&key)
        .execute(pool)
        .await;

        let limit = self.budget as i64;
        let cost_i64 = cost as i64;

        match sqlx::query(
            "UPDATE mcp_stats SET stat_value = stat_value + $1 WHERE stat_key = $2 AND stat_value + $1 <= $3 RETURNING stat_value"
        )
        .bind(cost_i64)
        .bind(&key)
        .bind(limit)
        .fetch_optional(pool)
        .await
        {
            Ok(Some(row)) => {
                use sqlx::Row;
                let new_val: i64 = row.get(0);
                self.used.store(new_val as u32, Ordering::Release);
                true
            }
            _ => {
                let current_used = self.used.load(Ordering::Acquire);
                let window_str = match self.window {
                    BudgetWindow::Daily => "Daily",
                    BudgetWindow::Monthly => "Monthly",
                };
                warn!("⚠️ SENTINEL: {} budget reached ({}/{}). Skipping high-cost API call.", window_str, current_used, self.budget);
                false
            }
        }
    }
}

pub struct ApiBudgetRegistry {
    managers: HashMap<String, CreditManager>,
    pool: Option<sqlx::PgPool>,
}

static REGISTRY: OnceLock<ApiBudgetRegistry> = OnceLock::new();

impl ApiBudgetRegistry {
    pub fn init(_config: &crate::utils::config::Config, pool: Option<sqlx::PgPool>) {
        let mut managers = HashMap::new();

        let netlas_budget = std::env::var("NETLAS_BUDGET").ok().and_then(|v| v.parse().ok()).unwrap_or(1000);
        let shodan_student_budget = std::env::var("SHODAN_STUDENT_BUDGET").ok().and_then(|v| v.parse().ok()).unwrap_or(100);
        let shodan_paid_budget = std::env::var("SHODAN_PAID_BUDGET").ok().and_then(|v| v.parse().ok()).unwrap_or(100);
        let securitytrails_budget = std::env::var("SECURITYTRAILS_BUDGET").ok().and_then(|v| v.parse().ok()).unwrap_or(50);
        let criminalip_budget = std::env::var("CRIMINALIP_BUDGET").ok().and_then(|v| v.parse().ok()).unwrap_or(1000);
        let zoomeye_budget = std::env::var("ZOOMEYE_BUDGET").ok().and_then(|v| v.parse().ok()).unwrap_or(10000);
        let greynoise_budget = std::env::var("GREYNOISE_BUDGET").ok().and_then(|v| v.parse().ok()).unwrap_or(1000);
        let fofa_budget = std::env::var("FOFA_BUDGET").ok().and_then(|v| v.parse().ok()).unwrap_or(10000);
        let chaos_budget = std::env::var("CHAOS_BUDGET").ok().and_then(|v| v.parse().ok()).unwrap_or(1000);

        managers.insert(
            "netlas".to_string(),
            CreditManager::new(netlas_budget, BudgetWindow::Monthly),
        );
        managers.insert(
            "shodan_student".to_string(),
            CreditManager::new(shodan_student_budget, BudgetWindow::Monthly),
        );
        managers.insert(
            "shodan_paid".to_string(),
            CreditManager::new(shodan_paid_budget, BudgetWindow::Monthly),
        );
        managers.insert(
            "securitytrails".to_string(),
            CreditManager::new(securitytrails_budget, BudgetWindow::Monthly),
        );
        managers.insert(
            "criminalip".to_string(),
            CreditManager::new(criminalip_budget, BudgetWindow::Monthly),
        );
        managers.insert(
            "zoomeye".to_string(),
            CreditManager::new(zoomeye_budget, BudgetWindow::Monthly),
        );
        managers.insert(
            "greynoise".to_string(),
            CreditManager::new(greynoise_budget, BudgetWindow::Monthly),
        );
        managers.insert(
            "fofa".to_string(),
            CreditManager::new(fofa_budget, BudgetWindow::Monthly),
        );
        managers.insert(
            "chaos".to_string(),
            CreditManager::new(chaos_budget, BudgetWindow::Monthly),
        );

        let registry = Self { managers, pool };
        let _ = REGISTRY.set(registry);
    }

    pub fn get() -> &'static Self {
        REGISTRY.get().expect("ApiBudgetRegistry must be initialized")
    }

    pub async fn can_spend(&self, source: &str, cost: u32) -> bool {
        if let Some(manager) = self.managers.get(source) {
            let allowed = if let Some(ref pool) = self.pool {
                manager.can_spend_db(pool, source, cost).await
            } else {
                manager.can_spend_mem(cost)
            };

            if !allowed {
                METRIC_BUDGET_SKIPS.fetch_add(1, Ordering::Relaxed);
            }
            allowed
        } else {
            warn!("⚠️ SENTINEL: Unknown budget source '{}'. Rejecting spend.", source);
            METRIC_UNKNOWN_SOURCE.fetch_add(1, Ordering::Relaxed);
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_budget_lost_increment_on_panic() {
        let manager = CreditManager::new(5, BudgetWindow::Monthly);
        
        let handle = std::thread::spawn(move || {
            let allowed = manager.can_spend_mem(1);
            assert!(allowed);
            panic!("worker panic simulation");
        });
        
        let _ = handle.join();
        
        let manager2 = CreditManager::new(5, BudgetWindow::Monthly);
        assert!(manager2.can_spend_mem(4));
        assert!(!manager2.can_spend_mem(2));
    }

    #[tokio::test]
    async fn test_budget_two_workers_concurrent_startup() {
        let manager = std::sync::Arc::new(CreditManager::new(10, BudgetWindow::Monthly));
        let mut handles = vec![];
        
        for _ in 0..10 {
            let m = manager.clone();
            handles.push(tokio::spawn(async move {
                m.can_spend_mem(1)
            }));
        }
        
        let mut success_count = 0;
        for h in handles {
            if h.await.unwrap() {
                success_count += 1;
            }
        }
        
        assert_eq!(success_count, 10);
        assert!(!manager.can_spend_mem(1));
    }

    #[tokio::test]
    async fn test_database_budget_sync() {
        let db_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| "postgres://osintuser:WENYANULTRA_SECURE_PASS@localhost:5432/osintdb".to_string());
        let pool = match sqlx::PgPool::connect(&db_url).await {
            Ok(p) => p,
            _ => {
                info!("Skipping database-backed budget tests (no DB available)");
                return;
            }
        };

        let test_key = "budget:test_source:";
        let _ = sqlx::query("DELETE FROM mcp_stats WHERE stat_key LIKE $1")
            .bind(format!("{}%", test_key))
            .execute(&pool)
            .await;

        let manager = CreditManager::new(5, BudgetWindow::Monthly);
        
        let ok1 = manager.can_spend_db(&pool, "test_source", 3).await;
        assert!(ok1);

        let ok2 = manager.can_spend_db(&pool, "test_source", 2).await;
        assert!(ok2);

        let ok3 = manager.can_spend_db(&pool, "test_source", 1).await;
        assert!(!ok3);
    }
}
