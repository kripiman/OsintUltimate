use tracing::{info, warn};
use crate::models::{TargetHost, Finding, Category, Severity, TargetStatus};
use crate::core::policy::PolicyProvider;
use std::sync::Arc;

pub fn check_scope(
    target: &mut TargetHost,
    policy: &Arc<dyn PolicyProvider>,
    strict_scope: bool,
) -> bool {
    if !policy.is_target_allowed(&target.host) {
        if strict_scope {
            warn!("🛡️ V14.2 SCOPE: Target '{}' is OUT OF SCOPE. Rejecting (Fail-Closed).", target.host);
            target.status = TargetStatus::Dead;
            target.version += 1;
            let mut findings = (*target.findings).clone();
            findings.push(Finding::new(
                "SCOPE_VIOLATION",
                Category::Misconfiguration,
                Severity::Critical,
                &format!("Target '{}' is out of authorized scope!", target.host),
                serde_json::json!({"host": target.host})
            ));
            target.findings = Arc::new(findings);
            return false;
        } else {
            info!("🛡️ V14.2 SCOPE: Target '{}' is out of scope but strict_scope is DISABLED. Proceeding with caution.", target.host);
        }
    }
    true
}
