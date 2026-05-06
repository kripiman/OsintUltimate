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
    InformationGathering,
    HTTPRequestSmuggling,
    JsAnalysis,
    IdorDetection,
    RaceConditionTesting,
    MassAssignmentTesting,
    UploadTesting,
    Evasion,
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
    pub exploit_difficulty: RiskLevel,
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
            exploit_difficulty: RiskLevel::Medium,
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

    fn as_c2_operator(&self) -> Option<&dyn crate::core::c2::C2Operator> {
        None
    }
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

impl Default for PluginRegistry {
    fn default() -> Self {
        Self::new()
    }
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


use crate::utils::executor::{StealthExecutor, ExecutorMode};

/// Global configuration shared across all plugins to ensure consistency and streamline initialization.
#[derive(Clone)]
pub struct GlobalConfig<M: ExecutorMode = crate::utils::executor::GhostMode> where M: Clone {
    pub insecure: bool,
    pub jitter: std::sync::Arc<crate::utils::common::HumanJitter>,
    pub proxy_manager: std::sync::Arc<crate::utils::proxy::ProxyManager>,
    pub nmap_options: NmapOptions,
    pub sandbox: std::sync::Arc<crate::core::sandbox::SandboxDispatcher>,
    pub policy: std::sync::Arc<dyn crate::core::policy::PolicyProvider>,
    pub executor: std::sync::Arc<StealthExecutor<M>>,
    pub budget: std::sync::Arc<crate::core::swarm::budget::TokenBudget>,
    pub correlation_engine: std::sync::Arc<tokio::sync::Mutex<crate::core::correlation::CorrelationEngine>>,
    pub stealth_policy: crate::plugins::detection_evasion::stealth_policy::StealthPolicy,
    pub mcp_token: Option<String>,
    pub nuclei_tags: Option<String>,
    pub nuclei_severity: Option<String>,
    pub nuclei_custom_templates: Option<String>,
    pub mobsf_url: Option<String>,
    pub mobsf_api_key: Option<String>,
    pub mobsf_timeout_secs: u64,
    pub vigil_url: Option<String>,
    pub vigil_api_key: Option<String>,
    pub rebuff_url: Option<String>,
    pub rebuff_api_token: Option<String>,
    pub policy_file: Option<String>,
    pub strict_scope: bool,
    pub nuclei_auto_update: bool,
    pub h1_username: Option<String>,
    pub h1_api_key: Option<String>,
    pub bugcrowd_api_key: Option<String>,
    pub intigriti_token: Option<String>,
    pub bb_program_handle: Option<String>,
}

impl<M: ExecutorMode> Default for GlobalConfig<M>
where M: Clone
 {
    fn default() -> Self {
        Self::new()
    }
}

impl<M: ExecutorMode> GlobalConfig<M> where M: Clone {
    pub fn new() -> Self {
        let policy = std::sync::Arc::new(crate::core::policy::StaticPolicy::new());
        let proxy_manager = std::sync::Arc::new(crate::utils::proxy::ProxyManager::new(
            Vec::new(),
            false,
            crate::utils::config::ProxyMode::Dante,
            0,
        ));
        let executor = std::sync::Arc::new(StealthExecutor::new(
            policy.clone(),
            Some(proxy_manager.clone()),
            false,
        ));
        let res_mgr = crate::core::resource_manager::SysResourceManager::new();
        let sandbox = std::sync::Arc::new(crate::core::sandbox::SandboxDispatcher::new(res_mgr).with_policy(policy.clone()));

        Self {
            insecure: false,
            jitter: std::sync::Arc::new(crate::utils::common::HumanJitter::new(100, 1500)),
            proxy_manager,
            nmap_options: NmapOptions {
                scripts: None,
                stealth: false,
                service_detection: false,
                scan_type: "connect".to_string(),
                fragment: false,
                decoy: None,
                ports: None,
                vuln_scan: false,
            },
            sandbox,
            policy: policy.clone(),
            executor,
            budget: std::sync::Arc::new(crate::core::swarm::budget::TokenBudget::new(50000)),
            correlation_engine: std::sync::Arc::new(tokio::sync::Mutex::new(crate::core::correlation::CorrelationEngine::new())),
            stealth_policy: crate::plugins::detection_evasion::stealth_policy::StealthPolicy::default(),
            mcp_token: None,
            nuclei_tags: None,
            nuclei_severity: None,
            nuclei_custom_templates: None,
            mobsf_url: None,
            mobsf_api_key: None,
            mobsf_timeout_secs: 600,
            vigil_url: None,
            vigil_api_key: None,
            rebuff_url: None,
            rebuff_api_token: None,
            policy_file: None,
            strict_scope: false,
            nuclei_auto_update: false,
            h1_username: None,
            h1_api_key: None,
            bugcrowd_api_key: None,
            intigriti_token: None,
            bb_program_handle: None,
        }
    }
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

pub fn get_all_scanners<M: ExecutorMode>(config: GlobalConfig<M>) -> Vec<Box<dyn ScannerPlugin>> {
    use crate::plugins::enumeration::network::net::NmapScanner;
    use crate::plugins::enumeration::web::engine::WebFuzzer;
    use crate::plugins::enumeration::web::whatweb::WhatWebScanner;
    use crate::plugins::exploitation::web::sqlmap::SqlMapScanner;
    use crate::plugins::exploitation::network::hydra::HydraScanner;
    use crate::plugins::exploitation::web::wapiti::WapitiScanner;
    use crate::plugins::verification::zap::ZapScanner;
    use crate::plugins::verification::burp::BurpScanner;
    use crate::plugins::verification::caido::CaidoScanner;
    use crate::plugins::intelligence::nuclei::NucleiScanner;
    use crate::plugins::enumeration::web::ffuf::FfufScanner;
    use crate::plugins::enumeration::web::arjun::ArjunScanner;
    use crate::plugins::enumeration::network::rustscan::RustScanScanner;
    use crate::plugins::exploitation::network::netexec::NetExecScanner;
    use crate::plugins::reconnaissance::passive::trufflehog::TruffleHogScanner;
    use crate::plugins::exploitation::web::dalfox::DalfoxScanner;
    use crate::plugins::enumeration::web::katana::KatanaScanner;
    #[cfg(feature = "sovereign")]
    use crate::plugins::lateral_movement::bloodhound::BloodHoundScanner;
    use crate::plugins::exploitation::network::responder::ResponderScanner;
    use crate::plugins::exploitation::network::impacket::ImpacketScanner;
    #[cfg(feature = "sovereign")]
    use crate::plugins::privilege_escalation::certipy::CertipyScanner;
    use crate::plugins::exploitation::network::petitpotam::PetitPotamScanner;
    #[cfg(feature = "sovereign")]
    use crate::plugins::lateral_movement::sliver::SliverScanner;
    #[cfg(feature = "sovereign")]
    use crate::plugins::enumeration::cloud::scoutsuite::ScoutSuiteScanner;
    use crate::plugins::lateral_movement::ligolo::LigoloScanner;
    use crate::plugins::enumeration::cloud::pacu::PacuScanner;
    use crate::plugins::enumeration::cloud::cloudenum::CloudEnumScanner;
    use crate::plugins::reconnaissance::active::httpx::HttpxScanner;
    use crate::plugins::reconnaissance::active::naabu::NaabuScanner;
    use crate::plugins::enumeration::web::interactsh::InteractshScanner;
    #[cfg(feature = "sovereign")]
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
    use crate::plugins::reconnaissance::passive::waymore::WaymoreScanner;
    use crate::plugins::intelligence::jaeles::JaelesScanner;
    use crate::plugins::enumeration::cloud::prowler::ProwlerScanner;
    use crate::plugins::enumeration::cloud::kubebench::KubeBenchScanner;
    use crate::plugins::compliance::osv_scanner::OSVScanner;
    use crate::plugins::enumeration::web::crlfuzz::CRLFScanner;
    use crate::plugins::enumeration::web::gf::GfScanner;
    use crate::plugins::exploitation::web::commix::CommixScanner;
    #[cfg(feature = "sovereign")]
    use crate::plugins::privilege_escalation::privesc_hunter::{PrivescHunterScanner, PrivescCheckLevel};
    use crate::plugins::exploitation::web::graphql_cop::GraphQLCopScanner; // NUEVO
    use crate::plugins::exploitation::network::coercer::CoercerScanner; // NUEVO
    use crate::plugins::enumeration::web::jsluice::JsluiceScanner; // NUEVO
    use crate::plugins::reconnaissance::active::subzy::SubzyScanner; // NUEVO
    use crate::plugins::exploitation::web::nomore403::NoMore403Scanner; // NUEVO
    use crate::plugins::exploitation::web::smuggler::SmugglerScanner; // NUEVO
    use crate::plugins::intelligence::greynoise::GreyNoiseScanner; // NUEVO
    use crate::plugins::enumeration::web::x8::X8Scanner; // NUEVO
    use crate::plugins::enumeration::web::inql::InQLScanner; // NUEVO
    use crate::plugins::enumeration::web::ppmap::PpmapScanner; // NUEVO
    use crate::plugins::enumeration::web::corsy::CorsyScanner; // NUEVO
    use crate::plugins::enumeration::web::wcd::WcdScanner; // NUEVO
    use crate::plugins::exploitation::web::ssrf_king::SsrfKingScanner;
    use crate::plugins::exploitation::web::tplmap::TplmapScanner;
    use crate::plugins::exploitation::web::openredirex::OpenRedirexScanner;
    use crate::plugins::enumeration::web::linkfinder::LinkFinderScanner;
    use crate::plugins::enumeration::web::secretfinder::SecretFinderScanner;
    use crate::plugins::enumeration::web::js_deep::{SubJSScanner, RetireScanner, SourceMapperScanner};
    use crate::plugins::exploitation::web::upload_strike::UploadStrikeScanner;
    use crate::plugins::exploitation::web::business_logic::BusinessLogicScanner;

    #[cfg(feature = "ai-redteam")]
    use crate::plugins::exploitation::ai_llm::garak::GarakScanner;
    #[cfg(feature = "ai-redteam")]
    use crate::plugins::exploitation::ai_llm::promptmap::PromptmapScanner;
    #[cfg(feature = "ai-redteam")]
    use crate::plugins::exploitation::ai_llm::llmfuzzer::LLMFuzzerScanner;
    #[cfg(feature = "ai-redteam")]
    use crate::plugins::exploitation::ai_llm::pyrit::PyRITScanner;
    #[cfg(feature = "ai-redteam")]
    use crate::plugins::exploitation::ai_llm::promptfoo::PromptfooScanner;
    #[cfg(feature = "ai-redteam")]
    use crate::plugins::exploitation::ai_llm::promptinject::PromptInjectScanner;
    #[cfg(feature = "ai-redteam")]
    use crate::plugins::exploitation::ai_llm::vigil::VigilScanner;
    #[cfg(feature = "ai-redteam")]
    use crate::plugins::exploitation::ai_llm::modelscan::ModelScanScanner;
    #[cfg(feature = "ai-redteam")]
    use crate::plugins::exploitation::ai_llm::rebuff::RebuffScanner;
    
    #[cfg(feature = "mobile")]
    use crate::plugins::exploitation::mobile::mobsf::MobSFScanner;
    #[cfg(feature = "mobile")]
    use crate::plugins::exploitation::mobile::apkleaks::APKLeaksScanner;
    #[cfg(feature = "mobile")]
    use crate::plugins::exploitation::mobile::apktool::ApktoolScanner;
    #[cfg(feature = "mobile")]
    use crate::plugins::exploitation::mobile::jadx::JadxScanner;
    #[cfg(feature = "mobile")]
    use crate::plugins::exploitation::mobile::drozer::DrozerScanner;
    #[cfg(feature = "mobile")]
    use crate::plugins::exploitation::mobile::frida::FridaScanner;
    #[cfg(feature = "mobile")]
    use crate::plugins::exploitation::mobile::objection::ObjectionScanner;
    #[cfg(feature = "mobile")]
    use crate::plugins::exploitation::mobile::mariana_trench::MarianaTrenchScanner;

    #[cfg_attr(not(any(feature = "ai-redteam", feature = "mobile")), allow(unused_mut))]
    let mut scanners: Vec<Box<dyn ScannerPlugin>> = vec![
        Box::new(WebFuzzer::new(config.insecure, config.jitter.clone(), Some(config.proxy_manager.clone()))), 
        Box::new(NmapScanner::new(
            config.nmap_options.scripts.clone(), config.nmap_options.stealth, config.nmap_options.service_detection, config.nmap_options.scan_type.clone(), config.nmap_options.fragment, config.nmap_options.decoy.clone(), config.nmap_options.ports.clone(), config.nmap_options.vuln_scan, config.executor.clone())), 
        Box::new(WhatWebScanner::new(config.executor.clone())), 
        Box::new(SqlMapScanner::new()), 
        Box::new(HydraScanner::new(None, None, None)), 
        Box::new(WapitiScanner::new()), 
        Box::new(ZapScanner::new(None, None, None)), 
        Box::new(BurpScanner::new(None, None)), 
        Box::new(NucleiScanner::new(config.clone())), 
        Box::new(FfufScanner::new(None)), 
        Box::new(ArjunScanner::new()), 
        Box::new(RustScanScanner::new()), 
        Box::new(NetExecScanner::new()), 
        Box::new(TruffleHogScanner::new()), 
        Box::new(DalfoxScanner::new()), 
        Box::new(KatanaScanner::new()), 
        #[cfg(feature = "sovereign")]
        Box::new(BloodHoundScanner::new(config.executor.clone(), config.correlation_engine.clone())), 
        Box::new(ResponderScanner::new()), 
        Box::new(ImpacketScanner::new()), 
        #[cfg(feature = "sovereign")]
        Box::new(CertipyScanner::new()), 
        Box::new(PetitPotamScanner::new()), 
        #[cfg(feature = "sovereign")]
        Box::new(SliverScanner::new(config.executor.clone())), 
        #[cfg(feature = "sovereign")]
        Box::new(ScoutSuiteScanner::new()),
        Box::new(LigoloScanner::new(config.executor.clone())), 
        Box::new(PacuScanner::new()), 
        Box::new(CloudEnumScanner::new()), 
        Box::new(HttpxScanner::new(config.proxy_manager.clone())), 
        Box::new(NaabuScanner::new()), 
        Box::new(InteractshScanner::new()), 
        #[cfg(feature = "sovereign")]
        Box::new(HavocScanner::new(config.executor.clone())), 
        Box::new(CloudFoxScanner::new()), 
        Box::new(KiterunnerScanner::new()), 
        Box::new(KubescapeScanner::new()), 
        Box::new(GitleaksScanner::new()), 
        Box::new(TsunamiScanner::new()), 
        Box::new(CheckovScanner::new()), 
        Box::new(JwtToolScanner::new()), 
        Box::new(GoWitnessScanner::new()), 
        Box::new(SearchsploitScanner::new()), 
        Box::new(TrivyScanner::new()), 
        Box::new(FeroxbusterScanner::new()), 
        Box::new(GauPlusScanner::new()), 
        Box::new(DnsxScanner::new(config.executor.clone())), 
        Box::new(CloudBruteScanner::new()), 
        Box::new(NiktoScanner::new()), 
        Box::new(WPScanner::new()), 
        Box::new(SnallygasterScanner::new()), 
        Box::new(WaybackScanner::new()), 
        Box::new(WaymoreScanner::new()),
        Box::new(JaelesScanner::new()), 
        Box::new(ProwlerScanner::new()), 
        Box::new(KubeBenchScanner::new()), 
        Box::new(OSVScanner::new()), 
        Box::new(CRLFScanner::new()), 
        Box::new(GfScanner::new()), 
        Box::new(CommixScanner::new()), 
        #[cfg(feature = "sovereign")]
        Box::new(PrivescHunterScanner::new(PrivescCheckLevel::Moderate)), 
        Box::new(GraphQLCopScanner::new()), 
        Box::new(CoercerScanner::new()), 
        Box::new(CaidoScanner::new(&crate::utils::config::Config::from_env(), config.proxy_manager.clone())), 
        Box::new(JsluiceScanner::new()),
        Box::new(SubzyScanner::new()),
        Box::new(NoMore403Scanner::new()),
        Box::new(SmugglerScanner::new()),
        Box::new(GreyNoiseScanner::new()),
        Box::new(X8Scanner::new()),
        Box::new(InQLScanner::new()),
        Box::new(compliance::syft::SyftScanner::new()),
        Box::new(compliance::grype::GrypeScanner::new()),
        Box::new(compliance::cosign::CosignScanner::new()),
        Box::new(PpmapScanner::new()),
        Box::new(CorsyScanner::new()),
        Box::new(WcdScanner::new()),
        Box::new(SsrfKingScanner::new(config.proxy_manager.clone())),
        Box::new(TplmapScanner::new()),
        Box::new(OpenRedirexScanner::new()),
        Box::new(LinkFinderScanner::new(&config)),
        Box::new(enumeration::web::api::graphw00f::GraphW00fScanner::new()),
        Box::new(enumeration::web::api::schemathesis::SchemathesisScanner::new()),
        Box::new(enumeration::web::api::crackql::CrackqlScanner::new()),
        Box::new(SecretFinderScanner::new(&config)),
        Box::new(SubJSScanner::new()),
        Box::new(RetireScanner::new()),
        Box::new(SourceMapperScanner::new()),
        Box::new(UploadStrikeScanner::new(Some(config.proxy_manager.clone()))),
        Box::new(BusinessLogicScanner::new(Some(config.proxy_manager.clone()))),
    ];

    #[cfg(feature = "ai-redteam")]
    {
        scanners.push(Box::new(GarakScanner::new(config.clone())));
        scanners.push(Box::new(PromptmapScanner::new(config.clone())));
        scanners.push(Box::new(LLMFuzzerScanner::new(config.clone())));
        scanners.push(Box::new(PyRITScanner::new(&config)));
        scanners.push(Box::new(PromptfooScanner::new(&config)));
        scanners.push(Box::new(PromptInjectScanner::new(&config)));
        scanners.push(Box::new(VigilScanner::<M>::new(
            config.vigil_url.clone().unwrap_or_else(|| "http://localhost:5000".to_string()),
            config.vigil_api_key.clone().unwrap_or_default()
        )));
        scanners.push(Box::new(ModelScanScanner::<M>::new(&config)));
        scanners.push(Box::new(RebuffScanner::<M>::new(
            config.rebuff_url.clone().unwrap_or_else(|| "http://localhost:3000".to_string()),
            config.rebuff_api_token.clone().unwrap_or_default()
        )));
    }

    #[cfg(feature = "mobile")]
    {
        scanners.push(Box::new(compliance::syft::SyftScanner::new()));
        scanners.push(Box::new(compliance::grype::GrypeScanner::new()));
        scanners.push(Box::new(compliance::cosign::CosignScanner::new()));
        scanners.push(Box::new(APKLeaksScanner::new(&config)));
        scanners.push(Box::new(ApktoolScanner::new()));
        scanners.push(Box::new(JadxScanner::new()));
        scanners.push(Box::new(DrozerScanner::new()));
        scanners.push(Box::new(FridaScanner::new()));
        scanners.push(Box::new(ObjectionScanner::new()));
        scanners.push(Box::new(MarianaTrenchScanner::new()));
        if let (Some(url), Some(key)) = (&config.mobsf_url, &config.mobsf_api_key) {
            // Hardening: Skip placeholder or invalid keys
            if !key.is_empty() && !key.starts_with("YOUR_") && key.len() > 10 {
                scanners.push(Box::new(MobSFScanner::<M>::new(url.clone(), key.clone(), config.mobsf_timeout_secs)));
            } else {
                tracing::warn!("MobSF API Key is missing, empty or using placeholder. Skipping MobSFScanner.");
            }
        }
    }

    scanners
}

pub fn get_all_discovery<M: ExecutorMode>(config: GlobalConfig<M>) -> Vec<Box<dyn DiscoveryPlugin>> {
    use crate::plugins::reconnaissance::osint::engine::OsintScanner;
    use crate::plugins::reconnaissance::osint::subfinder::SubfinderScanner;
    use crate::plugins::reconnaissance::osint::amass::AmassScanner;
    use crate::plugins::reconnaissance::osint::uncover::UncoverScanner;
    use crate::plugins::reconnaissance::osint::sovereign_recon::SovereignReconScanner;
    use crate::plugins::reconnaissance::osint::alterx::AlterXScanner;

    vec![
        Box::new(SovereignReconScanner::new(&crate::utils::config::Config::from_env(), config.proxy_manager.clone())),
        Box::new(OsintScanner::new(config.proxy_manager.clone())), 
        Box::new(SubfinderScanner::new(config.proxy_manager.clone())), 
        Box::new(AmassScanner::new()),
        Box::new(UncoverScanner::new()), 
        Box::new(AlterXScanner::new()),
    ]
}

pub fn get_registry<M: ExecutorMode>(config: GlobalConfig<M>) -> PluginRegistry {
    let mut registry = PluginRegistry::new();
    
    for scanner in get_all_scanners(config.clone()) {
        registry.add_scanner(scanner);
    }
    
    for discovery in get_all_discovery(config) {
        registry.add_discovery(discovery);
    }
    
    registry
}
