/// handlers/mod.rs — Facade re-exports + Item 5 from PLAN v3 6.B mapping table.
/// pub fn get_current_stats (L104–L119) — shared helper used by findings_stream
///
/// All 18 items mapped to submodules; facade re-exports maintain the public API surface
/// so that `handlers::get_targets`, `handlers::findings_stream`, etc. remain valid paths.
pub mod approvals;
pub mod credentials;
pub mod findings;
pub mod missions;
pub mod mobile;
pub mod reports;
pub mod status;
pub mod targets;

pub use approvals::{get_approvals, post_approval_decision, ApprovalDecisionPayload};
pub use credentials::get_credentials;
pub use findings::{findings_stream, get_stats_handler, get_metrics, get_roi_rankings};
pub use missions::submit_mission;
pub use mobile::submit_mobile_scan;
pub use reports::export_report;
pub use status::{get_swarm_status, get_containers};
pub use targets::{TargetsQuery, get_targets, get_target_findings, get_attack_graph};

use super::models::DashboardStats;
use super::state::DashboardState;

/// Item 5: shared stats helper used by findings_stream and get_stats_handler.
pub fn get_current_stats(state: &DashboardState) -> DashboardStats {
    let mut sys = sysinfo::System::new_all();
    sys.refresh_all();

    let tokens = state.budget.as_ref().map(|b| b.current_total()).unwrap_or(0);
    let limit = state.budget.as_ref().map(|b| b.max_tokens).unwrap_or(0);

    DashboardStats {
        ram_mb: sys.used_memory() / 1024 / 1024,
        ram_limit_mb: state.ram_limit_mb,
        active_threads: 0,
        active_proxies: 0,
        tokens_used: tokens,
        token_limit: limit,
    }
}
