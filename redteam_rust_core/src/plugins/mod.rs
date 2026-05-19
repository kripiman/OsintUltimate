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
