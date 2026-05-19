use serde::{Deserialize, Serialize};
use std::path::Path;
use anyhow::{Context, Result};
pub mod rubric;

use self::rubric::ScopeDifficulty;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramMetrics {
    pub name: String,
    /// Median payout for bounties in USD.
    pub median_payout: f64,
    /// Total reports resolved. Used as a proxy for program activity.
    pub resolved_reports: u32,
    /// Months since program launch.
    pub age_months: u32,
    /// Success Rate (0.0 to 1.0).
    /// H1: "Resolved" / "Submitted" ratio.
    /// BC: "Validity rate" public stat.
    pub success_rate: f64,
    pub difficulty: ScopeDifficulty,
}

impl ProgramMetrics {
    /// Calculates the ROI Score to prioritize targets.
    /// Higher is better.
    pub fn calculate_roi_score(&self) -> f64 {
        let age_factor = self::rubric::get_age_factor(self.age_months);
        let diff_factor = self.difficulty.as_factor();
        
        // Anti-Saturation proven bonus: Differentiates between hot fresh targets and forgotten gems.
        let proven_bonus = self::rubric::calculate_proven_bonus(self.age_months, self.resolved_reports);

        // Cost proxy = age * difficulty. Guard against zero div.
        let cost = (age_factor as f64 * diff_factor as f64).max(0.1);
        
        // ROI = (Reward * Probability * Bonus) / Cost
        // NOTE: High payout often correlates with higher rejection rates in reality.
        let score = (self.median_payout * self.success_rate * proven_bonus) / cost;
        
        if score.is_nan() || score.is_infinite() {
            0.0
        } else {
            score
        }
    }
}

/// Orchestrates program selection and ranking based on ROI metrics.
/// 
/// NOTE: Currently stateless. In future phases, this will maintain:
/// - Cache of program metrics to avoid redundant file I/O.
/// - Dynamic weights from `CorrelationEngine` (Fase 4 feedback loop).
#[derive(Default)]
pub struct ProgramAnalyzer;

impl ProgramAnalyzer {
    pub fn new() -> Self {
        Self
    }

    /// Ranks a list of programs by their ROI score.
    pub fn rank_programs(&self, programs: Vec<ProgramMetrics>) -> Vec<(String, f64)> {
        let mut ranked: Vec<_> = programs.into_iter()
            .map(|p| {
                let score = p.calculate_roi_score();
                (p.name, score)
            })
            .collect();

        // Sort by score descending
        ranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        ranked
    }

    /// Loads program data from a JSON file.
    pub fn load_from_json<P: AsRef<Path>>(&self, path: P) -> Result<Vec<ProgramMetrics>> {
        let content = std::fs::read_to_string(path).context("Failed to read program data file")?;
        serde_json::from_str(&content).context("Failed to parse program metrics JSON")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::selection::rubric::ScopeDifficulty;

    #[test]
    fn test_fresh_high_payout_outranks_old_saturated() {
        let fresh = ProgramMetrics {
            name: "fresh_program".into(),
            median_payout: 1000.0,
            resolved_reports: 5,
            age_months: 3,
            success_rate: 0.5,
            difficulty: ScopeDifficulty::WildcardStandard,
        };

        let old = ProgramMetrics {
            name: "old_saturated".into(),
            median_payout: 1000.0,
            resolved_reports: 5000,
            age_months: 60,
            success_rate: 0.5,
            difficulty: ScopeDifficulty::WildcardStandard,
        };

        let analyzer = ProgramAnalyzer::new();
        let ranked = analyzer.rank_programs(vec![old.clone(), fresh.clone()]);
        
        assert_eq!(ranked[0].0, "fresh_program");
        assert!(ranked[0].1 > ranked[1].1);
    }

    #[test]
    fn test_zero_inputs_no_panic() {
        let bad = ProgramMetrics {
            name: "bad".into(),
            median_payout: 0.0,
            resolved_reports: 0,
            age_months: 0,
            success_rate: 0.0,
            difficulty: ScopeDifficulty::SingleTld,
        };
        let score = bad.calculate_roi_score();
        assert_eq!(score, 0.0);
    }

    #[test]
    fn test_nan_protection() {
        let nan_input = ProgramMetrics {
            name: "nan".into(),
            median_payout: 1000.0,
            resolved_reports: 10,
            age_months: 6,
            success_rate: f64::NAN,
            difficulty: ScopeDifficulty::WildcardStandard,
        };
        assert_eq!(nan_input.calculate_roi_score(), 0.0);
    }

    #[test]
    fn test_forgotten_gem_outranks_saturated_same_age() {
        let saturated = ProgramMetrics {
            name: "saturated".into(),
            median_payout: 1000.0,
            resolved_reports: 5000,
            age_months: 30, // > 24m
            success_rate: 0.5,
            difficulty: ScopeDifficulty::WildcardStandard,
        };

        let forgotten_gem = ProgramMetrics {
            name: "forgotten_gem".into(),
            median_payout: 1000.0,
            resolved_reports: 10, // < 50
            age_months: 30,
            success_rate: 0.5,
            difficulty: ScopeDifficulty::WildcardStandard,
        };

        let analyzer = ProgramAnalyzer::new();
        let ranked = analyzer.rank_programs(vec![saturated.clone(), forgotten_gem.clone()]);
        
        assert_eq!(ranked[0].0, "forgotten_gem");
        assert!(ranked[0].1 > ranked[1].1); // 1.5x bonus vs 1.0x
    }
}
