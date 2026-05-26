pub mod reconnaissance;
pub mod enumeration;
pub mod exploitation;
#[cfg(feature = "sovereign")]
pub mod lateral_movement;
#[cfg(feature = "sovereign")]
pub mod persistence;
#[cfg(feature = "sovereign")]
pub mod privilege_escalation;
pub mod compliance;
pub mod detection_evasion;
pub mod intelligence;
pub mod verification;
pub mod reporting;
pub mod triage;

pub mod ffi;

// New flat factories/submodules
pub mod config;
pub mod registry;
pub mod scanner_factory;
pub mod discovery_factory;

use async_trait::async_trait;
pub use crate::models::{TargetHost, Finding, constants, TargetType, DiscoveryResult};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use crate::core::capability_layer::ScanLayer;

// Facade re-exports to preserve exact public API
pub use config::{GlobalConfig, NmapOptions};
pub use registry::{PluginRegistry, get_registry};
pub use scanner_factory::get_all_scanners;
pub use discovery_factory::get_all_discovery;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Capability {
    PortScanning,
    ServiceDiscovery,
    VulnerabilityScanning,
    WebFuzzing,
    SecretDiscovery,
    WafDetection,
    CloudAudit,
    ActiveDirectory,
    OsintDiscovery,
    SubdomainEnumeration,
    HistoricalRecon,
    InfrastructureAudit,
    ConfigAudit,
    IAMAssessment,
    SCA,
    SecurityAuditing,
    GraphQL,
    ApiSecurity,
    K8sAudit,
    ContainerSecurity,
    AdCoercion,
    PrivilegeEscalation,
    BruteForce,         // NUEVO
    CommandInjection,    // NUEVO
    XssScanning,         // NUEVO
    SqlInjection,        // NUEVO
    DirectoryBruteForce, // NUEVO
    InformationGathering,
    HTTPRequestSmuggling,
    JsAnalysis,
    IdorDetection,
    RaceConditionTesting,
    MassAssignmentTesting,
    UploadTesting,
    Evasion,
    AsnMapping,
    CdnDetection,
    TlsFingerprinting,
    ScopeExtraction,
    AuthStateMachine,   // V14.6: Stateful OAuth/custom auth flow probing
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    Safe,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PluginStatus {
    Running,
    Idle,
    Crashed(String),
    Suspended,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginMetadata {
    pub name: String,
    pub description: String,
    pub target_type: TargetType,
    pub risk_level: RiskLevel,
    pub layer: ScanLayer,
    pub category: String, // E.g., "Web", "Network", "Cloud"
    pub expected_duration: std::time::Duration,
    pub capabilities: Vec<Capability>,
    pub cost: u32,
    pub mitre_attacks: Vec<String>, // E.g., ["T1110", "T1046"]
    pub exploit_difficulty: RiskLevel,
    pub blackarch_category: Option<String>, // NUEVO: Categoría oficial de BlackArch
    pub is_destructive: bool, // NUEVO: Indica si la acción puede alterar el estado o causar DoS
    pub poc_mode: bool,       // NUEVO: Indica si el plugin tiene un modo de prueba no intrusivo
    pub is_monitor: bool,     // NUEVO: Indica si el plugin es de larga duración (I3/I7)
}

impl Default for PluginMetadata {
    fn default() -> Self {
        Self {
            name: "Unknown Plugin".to_string(),
            description: "No description provided.".to_string(),
            target_type: TargetType::Host,
            risk_level: RiskLevel::Medium,
            layer: ScanLayer::Scanning,
            category: "General".to_string(),
            expected_duration: std::time::Duration::from_secs(60),
            capabilities: Vec::new(),
            cost: 1,
            mitre_attacks: Vec::new(),
            exploit_difficulty: RiskLevel::Medium,
            blackarch_category: None,
            is_destructive: false,
            poc_mode: true,
            is_monitor: false,
        }
    }
}

#[async_trait]
pub trait ScannerPlugin: Send + Sync {
    fn name(&self) -> &'static str;
    fn metadata(&self) -> PluginMetadata;
    fn capabilities(&self) -> Vec<Capability>;
    async fn check_dependencies(&self) -> Result<bool>;
    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>>;

    async fn execute_safe_scan(
        &self,
        target: &TargetHost,
        policy: std::sync::Arc<dyn crate::core::policy::PolicyProvider>,
        strict_scope: bool,
        approval_gate: std::sync::Arc<crate::core::approval_gate::ApprovalGate>,
        approval_timeout_secs: Option<u64>
    ) -> Result<Vec<Finding>> {
        // 1. Enforce Scope using existing scope_guard
        let mut target_clone = target.clone();
        if !crate::core::orchestrator::scope_guard::check_scope(&mut target_clone, &policy, strict_scope) {
            return Ok((*target_clone.findings).clone());
        }

        // 2. Enforce Destructive Gate
        if self.metadata().is_destructive {
            let config_allow = target.tactical_context
                .get("allow_destructive_probes")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            if !config_allow {
                tracing::warn!("Destructive plugin {} blocked: allow_destructive_probes not set in tactical_context", self.name());
                return Ok(vec![]);
            }

            // Gate: Env Var
            if std::env::var("REDTEAM_DESTRUCTIVE").as_deref() != Ok("1") {
                tracing::warn!("Destructive plugin {} blocked: REDTEAM_DESTRUCTIVE not set", self.name());
                return Ok(vec![]);
            }

            // Gate 2: ApprovalGate (Dynamic risk and timeout)
            let risk = match self.metadata().risk_level {
                RiskLevel::Critical => 90u8,
                RiskLevel::High => 70,
                _ => 50,
            };

            let user = crate::core::approval_gate::User {
                id: "system".to_string(),
                name: "Orchestrator".to_string(),
                role: crate::core::approval_gate::UserRole::Administrator,
                authorized_at: chrono::Utc::now(),
            };

            let timeout = approval_timeout_secs
                .or_else(|| std::env::var("REDTEAM_APPROVAL_TIMEOUT").ok().and_then(|v| v.parse().ok()))
                .unwrap_or(300);

            if let Ok(Some(req_id)) = approval_gate.request_approval(self.name(), risk, &user, "Automated destructive execution").await {
                if !approval_gate.wait_for_approval(&req_id, timeout).await {
                    tracing::warn!("Destructive plugin {} timed out or rejected.", self.name());
                    return Ok(vec![]);
                }
            }
        }

        // 3. Delegate to actual plugin
        self.scan(target).await
    }

    async fn poll_status(&self) -> Result<PluginStatus> {
        Ok(PluginStatus::Running)
    }

    async fn stop(&self) -> Result<()> {
        Ok(())
    }

    fn as_c2_operator(&self) -> Option<&dyn crate::core::orchestrator::c2::C2Operator> {
        None
    }

    fn set_feedback_channel(&self, _tx: tokio::sync::mpsc::Sender<TargetHost>) {}
}

#[async_trait]
pub trait DiscoveryPlugin: Send + Sync {
    fn name(&self) -> &'static str;
    fn metadata(&self) -> PluginMetadata;
    fn capabilities(&self) -> Vec<Capability>;
    async fn check_dependencies(&self) -> Result<bool>;
    async fn discover(&self, target: &TargetHost) -> Result<Vec<DiscoveryResult>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{TargetHost, TargetStatus, TargetType, Finding};
    use crate::core::approval_gate::ApprovalGate;
    use std::sync::Arc;
    use async_trait::async_trait;

    struct DummyPolicy;
    impl crate::core::policy::PolicyProvider for DummyPolicy {
        fn validate_command(&self, _binary: &str, _args: &[String]) -> Result<()> { Ok(()) }
        fn is_path_safe(&self, _path: &str) -> bool { true }
        fn is_target_allowed(&self, _target: &str) -> bool { true }
        fn is_within_testing_window(&self) -> bool { true }
        fn get_roe(&self) -> Option<crate::core::policy::RoE> { None }
    }

    struct DummyDestructivePlugin;

    #[async_trait]
    impl ScannerPlugin for DummyDestructivePlugin {
        fn name(&self) -> &'static str { "dummy_destructive" }
        fn metadata(&self) -> PluginMetadata {
            PluginMetadata {
                name: "dummy_destructive".to_string(),
                description: "Test destructive plugin".to_string(),
                layer: crate::core::capability_layer::ScanLayer::Exploitation,
                target_type: TargetType::Host,
                cost: 1,
                is_monitor: false,
                is_destructive: true,
                risk_level: RiskLevel::Critical,
                ..PluginMetadata::default()
            }
        }
        fn capabilities(&self) -> Vec<Capability> { vec![] }
        async fn check_dependencies(&self) -> Result<bool> { Ok(true) }
        async fn scan(&self, _target: &TargetHost) -> Result<Vec<Finding>> {
            Ok(vec![Finding::new(
                "TEST_FINDING",
                crate::models::Category::Vulnerability,
                crate::models::Severity::High,
                "Vulnerable",
                serde_json::json!({})
            )])
        }
    }

    #[tokio::test]
    async fn test_destructive_dual_gate() {
        let policy = Arc::new(DummyPolicy);
        let approval_gate = Arc::new(ApprovalGate::new(100));
        let plugin = DummyDestructivePlugin;

        // Case 1: Both gates missing
        std::env::remove_var("REDTEAM_DESTRUCTIVE");
        let target_no_config = TargetHost {
            host: "127.0.0.1".to_string(),
            ip: None,
            resolved_ip: None,
            target_type: TargetType::Host,
            file_path: None,
            user: None,
            status: TargetStatus::Pending,
            findings: Arc::new(vec![]),
            tool_suggestions: Arc::new(vec![]),
            tactical_context: Arc::new(serde_json::json!({})),
            extra_data: Arc::new(serde_json::json!({})),
            version: 1,
            skip_heavy_scan: false,
            scan_id: None,
            scope_id: "test".to_string(),
        };
        let res = plugin.execute_safe_scan(&target_no_config, policy.clone(), false, approval_gate.clone(), None).await.unwrap();
        assert!(res.is_empty(), "Scan should be blocked when both gates are missing");

        // Case 2: Only allow_destructive_probes set, env var missing
        let target_with_config = TargetHost {
            tactical_context: Arc::new(serde_json::json!({
                "allow_destructive_probes": true
            })),
            ..target_no_config.clone()
        };
        let res = plugin.execute_safe_scan(&target_with_config, policy.clone(), false, approval_gate.clone(), None).await.unwrap();
        assert!(res.is_empty(), "Scan should be blocked when env var is missing");

        // Case 3: Only env var set, config flag missing
        std::env::set_var("REDTEAM_DESTRUCTIVE", "1");
        let res = plugin.execute_safe_scan(&target_no_config, policy.clone(), false, approval_gate.clone(), None).await.unwrap();
        assert!(res.is_empty(), "Scan should be blocked when config flag is missing");

        // Case 4: Both gates set
        let res = plugin.execute_safe_scan(&target_with_config, policy.clone(), false, approval_gate.clone(), None).await.unwrap();
        assert_eq!(res.len(), 1, "Scan should proceed when both gates are set and approved");
    }
}
