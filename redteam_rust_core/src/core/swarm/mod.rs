pub mod budget;
pub mod orchestrator;
pub mod inventory;
pub mod nvd_monitor;

pub use budget::{TokenBudget, TokenGuard, TaskPriority};
pub use orchestrator::{SwarmConfig, SwarmOrchestrator, AgentRole};
pub use inventory::{SwarmInventory, TrustLevel, InventoryItem};
pub use nvd_monitor::NvdMonitor;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;

    #[test]
    fn test_token_budget_reservation() {
        let budget = TokenBudget::new(5000);
        
        // Reserve 2000 - should succeed
        assert!(budget.reserve_tokens(2000, TaskPriority::High));
        assert_eq!(budget.current_effective_total(), 2000);
        
        // Reserve another 2000 - should succeed
        assert!(budget.reserve_tokens(2000, TaskPriority::High));
        assert_eq!(budget.current_effective_total(), 4000);
        
        // Reserve 1500 - should fail (4000 + 1500 > 5000)
        assert!(!budget.reserve_tokens(1500, TaskPriority::High));
        assert_eq!(budget.current_effective_total(), 4000);
    }

    #[test]
    fn test_token_budget_commitment() {
        let budget = TokenBudget::new(5000);
        budget.reserve_tokens(1000, TaskPriority::Normal);
        
        // Commit 800 tokens, releasing 1000 reservation
        budget.commit_usage(800, 1000);
        
        assert_eq!(budget.current_total(), 800);
        assert_eq!(budget.current_effective_total(), 800);
        assert_eq!(budget.reserved_tokens.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_token_budget_exhaustion() {
        let budget = TokenBudget::new(1000);
        budget.reserve_tokens(900, TaskPriority::High);
        assert!(!budget.is_exhausted());
        
        budget.reserve_tokens(100, TaskPriority::High);
        assert!(budget.is_exhausted());
    }

    #[test]
    fn test_token_budget_per_agent_limit() {
        let budget = Arc::new(TokenBudget::new(10000).with_max_per_agent(1000));
        
        // Requesting 500 should succeed and stay 500
        let guard1 = TokenGuard::new(budget.clone(), 500, TaskPriority::High).unwrap();
        assert_eq!(guard1.amount, 500);
        
        // Requesting 2000 should be capped to 1000
        let guard2 = TokenGuard::new(budget.clone(), 2000, TaskPriority::High).unwrap();
        assert_eq!(guard2.amount, 1000);
    }
}
