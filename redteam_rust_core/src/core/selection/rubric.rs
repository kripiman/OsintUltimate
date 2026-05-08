use serde::{Deserialize, Serialize};

pub const PROVEN_BONUS_THRESHOLD: u32 = 50;
pub const HOT_FRESH_FACTOR: f64 = 1.3;
pub const FORGOTTEN_GEM_FACTOR: f64 = 1.5;
pub const DEFAULT_BONUS_FACTOR: f64 = 1.2;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ScopeDifficulty {
    /// Single TLD, no wildcard (Easy)
    SingleTld,
    /// Wildcard domain, standard web surface (Medium)
    WildcardStandard,
    /// JS-heavy / Massive microservices surface (Hard)
    MassiveJsHeavy,
    /// Mobile-only / Hardware / Exotic targets (Extreme)
    MobileHardwareIot,
}

impl ScopeDifficulty {
    pub fn as_factor(&self) -> f32 {
        match self {
            Self::SingleTld => 1.0,
            Self::WildcardStandard => 2.5,
            Self::MassiveJsHeavy => 4.0,
            Self::MobileHardwareIot => 5.0,
        }
    }
}

/// Rubric for program age factor.
/// Older programs are usually more saturated and harder to find fresh bugs.
pub fn get_age_factor(age_months: u32) -> f32 {
    if age_months < 6 {
        1.0 // Fresh / High volatility
    } else if age_months <= 24 {
        1.5 // Stable
    } else {
        3.0 // Saturated / High competition
    }
}

/// Calculates ROI bonus based on program age and reports.
/// Hot Fresh: New programs with low reports.
/// Forgotten Gem: Old programs with low reports.
pub fn calculate_proven_bonus(age_months: u32, resolved_reports: u32) -> f64 {
    match (age_months, resolved_reports) {
        (a, r) if a < 6 && r < PROVEN_BONUS_THRESHOLD => HOT_FRESH_FACTOR,
        (a, r) if a > 24 && r < PROVEN_BONUS_THRESHOLD => FORGOTTEN_GEM_FACTOR,
        // (_, r) if r < THRESHOLD: stable-age low-volume programs (mid-tier opportunity)
        (_, r) if r < PROVEN_BONUS_THRESHOLD => DEFAULT_BONUS_FACTOR,
        _ => 1.0,
    }
}
