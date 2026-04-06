pub mod reconnaissance;
pub mod enumeration;
pub mod exploitation;
pub mod lateral_movement;
pub mod persistence;
pub mod privilege_escalation;
pub mod detection_evasion;
pub mod intelligence;
pub mod verification;
pub mod compliance;
pub mod reporting;

pub mod ffi;

use async_trait::async_trait;
pub use crate::models::{TargetHost, Finding, TargetType};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use crate::core::capability_layer::ScanLayer;

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
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    Safe,
    Low,
    Medium,
    High,
    Critical,
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
    pub remediation_difficulty: RiskLevel,
    pub blackarch_category: Option<String>, // NUEVO: Categoría oficial de BlackArch
    pub is_destructive: bool, // NUEVO: Indica si la acción puede alterar el estado o causar DoS
    pub poc_mode: bool,       // NUEVO: Indica si el plugin tiene un modo de prueba no intrusivo
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
            remediation_difficulty: RiskLevel::Medium,
            blackarch_category: None,
            is_destructive: false,
            poc_mode: true,
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
}

#[async_trait]
pub trait DiscoveryPlugin: Send + Sync {
    fn name(&self) -> &'static str;
    fn metadata(&self) -> PluginMetadata;
    fn capabilities(&self) -> Vec<Capability>;
    async fn check_dependencies(&self) -> Result<bool>;
    async fn discover(&self, target: &TargetHost) -> Result<Vec<String>>;
}

pub struct PluginRegistry {
    pub scanners: Vec<Box<dyn ScannerPlugin>>,
    pub discovery: Vec<Box<dyn DiscoveryPlugin>>,
}

impl PluginRegistry {
    pub fn new() -> Self {
        Self {
            scanners: Vec::new(),
            discovery: Vec::new(),
        }
    }

    pub fn add_scanner(&mut self, scanner: Box<dyn ScannerPlugin>) {
        self.scanners.push(scanner);
    }

    pub fn add_discovery(&mut self, discovery: Box<dyn DiscoveryPlugin>) {
        self.discovery.push(discovery);
    }

    pub fn get_scanners_for_target(&self, target_type: TargetType) -> Vec<&dyn ScannerPlugin> {
        self.scanners.iter()
            .filter(|p| p.metadata().target_type == target_type)
            .map(|p| p.as_ref())
            .collect()
    }

    pub fn get_safe_scanners(&self) -> Vec<&dyn ScannerPlugin> {
        self.scanners.iter()
            .filter(|p| p.metadata().risk_level == RiskLevel::Safe)
            .map(|p| p.as_ref())
            .collect()
    }
}


/// Global configuration shared across all plugins to ensure consistency and streamline initialization.
#[derive(Clone)]
pub struct GlobalConfig {
    pub insecure: bool,
    pub jitter: std::sync::Arc<crate::utils::common::HumanJitter>,
    pub proxy_manager: Option<std::sync::Arc<crate::utils::proxy::ProxyManager>>,
    pub nmap_options: NmapOptions,
    pub sandbox: std::sync::Arc<crate::core::sandbox::SandboxDispatcher>, // NUEVO: Inyección del sandbox
}

#[derive(Clone, Serialize, Deserialize)]
pub struct NmapOptions {
    pub scripts: Option<String>,
    pub stealth: bool,
    pub service_detection: bool,
    pub scan_type: String,
    pub fragment: bool,
    pub decoy: Option<String>,
    pub ports: Option<String>,
    pub vuln_scan: bool,
}

pub fn get_all_scanners(config: GlobalConfig) -> Vec<Box<dyn ScannerPlugin>> {
    use crate::plugins::enumeration::network::net::NmapScanner;
    use crate::plugins::enumeration::web::web::WebFuzzer;
    use crate::plugins::enumeration::web::whatweb::WhatWebScanner;
    use crate::plugins::exploitation::web::sqlmap::SqlMapScanner;
    use crate::plugins::exploitation::network::hydra::HydraScanner;
    use crate::plugins::exploitation::web::wapiti::WapitiScanner;
    use crate::plugins::verification::zap::ZapScanner;
    use crate::plugins::verification::burp::BurpScanner;
    use crate::plugins::intelligence::nuclei::NucleiScanner;
    use crate::plugins::enumeration::web::ffuf::FfufScanner;
    use crate::plugins::enumeration::web::arjun::ArjunScanner;
    use crate::plugins::enumeration::network::rustscan::RustScanScanner;
    use crate::plugins::exploitation::network::netexec::NetExecScanner;
    use crate::plugins::reconnaissance::passive::trufflehog::TruffleHogScanner;
    use crate::plugins::exploitation::web::dalfox::DalfoxScanner;
    use crate::plugins::enumeration::web::katana::KatanaScanner;
    use crate::plugins::lateral_movement::bloodhound::BloodHoundScanner;
    use crate::plugins::exploitation::network::responder::ResponderScanner;
    use crate::plugins::exploitation::network::impacket::ImpacketScanner;
    use crate::plugins::privilege_escalation::certipy::CertipyScanner;
    use crate::plugins::exploitation::network::petitpotam::PetitPotamScanner;
    use crate::plugins::lateral_movement::sliver::SliverScanner;
    use crate::plugins::lateral_movement::ligolo::LigoloScanner;
    use crate::plugins::enumeration::cloud::pacu::PacuScanner;
    use crate::plugins::enumeration::cloud::cloudenum::CloudEnumScanner;
    use crate::plugins::reconnaissance::active::httpx::HttpxScanner;
    use crate::plugins::reconnaissance::active::naabu::NaabuScanner;
    use crate::plugins::enumeration::web::interactsh::InteractshScanner;
    use crate::plugins::persistence::havoc::HavocScanner;
    use crate::plugins::enumeration::cloud::cloudfox::CloudFoxScanner;
    use crate::plugins::enumeration::web::kiterunner::KiterunnerScanner;
    use crate::plugins::compliance::kubescape::KubescapeScanner;
    use crate::plugins::reconnaissance::passive::gitleaks::GitleaksScanner;
    use crate::plugins::enumeration::web::tsunami::TsunamiScanner;
    use crate::plugins::compliance::checkov::CheckovScanner;
    use crate::plugins::exploitation::web::jwt_tool::JwtToolScanner;
    use crate::plugins::enumeration::web::gowitness::GoWitnessScanner;
    use crate::plugins::intelligence::searchsploit::SearchsploitScanner;
    use crate::plugins::compliance::trivy::TrivyScanner;
    use crate::plugins::enumeration::web::feroxbuster::FeroxbusterScanner;
    use crate::plugins::enumeration::web::gauplus::GauPlusScanner;
    use crate::plugins::reconnaissance::active::dnsx::DnsxScanner;
    use crate::plugins::enumeration::cloud::cloudbrute::CloudBruteScanner;
    use crate::plugins::enumeration::web::nikto::NiktoScanner;
    use crate::plugins::enumeration::web::wpsec::WPScanner;
    use crate::plugins::enumeration::web::snallygaster::SnallygasterScanner;
    use crate::plugins::reconnaissance::passive::wayback::WaybackScanner;
    use crate::plugins::intelligence::jaeles::JaelesScanner;
    use crate::plugins::enumeration::cloud::prowler::ProwlerScanner;
    use crate::plugins::enumeration::cloud::kubebench::KubeBenchScanner;
    use crate::plugins::compliance::osv_scanner::OSVScanner;
    use crate::plugins::enumeration::web::crlfuzz::CRLFScanner;
    use crate::plugins::enumeration::web::gf::GfScanner;
    use crate::plugins::exploitation::web::commix::CommixScanner;
    use crate::plugins::privilege_escalation::privesc_hunter::{PrivescHunterScanner, PrivescCheckLevel};
    use crate::plugins::exploitation::web::graphql_cop::GraphQLCopScanner; // NUEVO
    use crate::plugins::exploitation::network::coercer::CoercerScanner; // NUEVO

    vec![Box::new(WebFuzzer::new(config.insecure, config.jitter.clone(), config.proxy_manager.clone())), Box::new(NmapScanner::new(
            config.nmap_options.scripts, config.nmap_options.stealth, config.nmap_options.service_detection, config.nmap_options.scan_type, config.nmap_options.fragment, config.nmap_options.decoy, config.nmap_options.ports, config.nmap_options.vuln_scan, config.sandbox.clone())), Box::new(WhatWebScanner::new()), Box::new(SqlMapScanner::new()), Box::new(HydraScanner::new(None, None, None)), Box::new(WapitiScanner::new()), Box::new(ZapScanner::new(None, None, None)), Box::new(BurpScanner::new(None, None)), Box::new(NucleiScanner::new()), Box::new(FfufScanner::new(None)), Box::new(ArjunScanner::new()), Box::new(RustScanScanner::new()), Box::new(NetExecScanner::new()), Box::new(TruffleHogScanner::new()), Box::new(DalfoxScanner::new()), Box::new(KatanaScanner::new()), Box::new(BloodHoundScanner::new()), Box::new(ResponderScanner::new()), Box::new(ImpacketScanner::new()), Box::new(CertipyScanner::new()), Box::new(PetitPotamScanner::new()), Box::new(SliverScanner::new()), Box::new(LigoloScanner::new()), Box::new(PacuScanner::new()), Box::new(CloudEnumScanner::new()), Box::new(HttpxScanner::new()), Box::new(NaabuScanner::new()), Box::new(InteractshScanner::new()), Box::new(HavocScanner::new()), Box::new(CloudFoxScanner::new()), Box::new(KiterunnerScanner::new()), Box::new(KubescapeScanner::new()), Box::new(GitleaksScanner::new()), Box::new(TsunamiScanner::new()), Box::new(CheckovScanner::new()), Box::new(JwtToolScanner::new()), Box::new(GoWitnessScanner::new()), Box::new(SearchsploitScanner::new()), Box::new(TrivyScanner::new()), Box::new(FeroxbusterScanner::new()), Box::new(GauPlusScanner::new()), Box::new(DnsxScanner::new()), Box::new(CloudBruteScanner::new()), Box::new(NiktoScanner::new()), Box::new(WPScanner::new()), Box::new(SnallygasterScanner::new()), Box::new(WaybackScanner::new()), Box::new(JaelesScanner::new()), Box::new(ProwlerScanner::new()), Box::new(KubeBenchScanner::new()), Box::new(OSVScanner::new()), Box::new(CRLFScanner::new()), Box::new(GfScanner::new()), Box::new(CommixScanner::new()), Box::new(PrivescHunterScanner::new(PrivescCheckLevel::Moderate)), Box::new(GraphQLCopScanner::new()), Box::new(CoercerScanner::new()), ]
}

pub fn get_all_discovery() -> Vec<Box<dyn DiscoveryPlugin>> {
    use crate::plugins::reconnaissance::osint::osint::OsintScanner;
    use crate::plugins::reconnaissance::osint::subfinder::SubfinderScanner;
    use crate::plugins::reconnaissance::osint::amass::AmassScanner;
    use crate::plugins::reconnaissance::osint::uncover::UncoverScanner;

    vec![Box::new(OsintScanner::new()), Box::new(SubfinderScanner::new()), Box::new(AmassScanner::new()), Box::new(UncoverScanner::new()), ]
}

pub fn get_registry(config: GlobalConfig) -> PluginRegistry {
    let mut registry = PluginRegistry::new();
    
    for scanner in get_all_scanners(config) {
        registry.add_scanner(scanner);
    }
    
    for discovery in get_all_discovery() {
        registry.add_discovery(discovery);
    }
    
    registry
}
