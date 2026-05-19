use crate::utils::executor::ExecutorMode;
use crate::plugins::config::GlobalConfig;
use crate::plugins::ScannerPlugin;

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
    use crate::plugins::enumeration::network::kerbrute::KerbruteScanner;
    use crate::plugins::enumeration::network::enum4linux::Enum4LinuxScanner;
    use crate::plugins::exploitation::network::netexec::NetExecScanner;
    use crate::plugins::reconnaissance::passive::trufflehog::TruffleHogScanner;
    use crate::plugins::exploitation::web::dalfox::DalfoxScanner;
    use crate::plugins::enumeration::web::katana::KatanaScanner;
    #[cfg(feature = "sovereign")]
    use crate::plugins::lateral_movement::bloodhound::BloodHoundScanner;
    #[cfg(feature = "sovereign")]
    use crate::plugins::exploitation::network::responder::ResponderScanner;
    #[cfg(feature = "sovereign")]
    use crate::plugins::exploitation::network::impacket::ImpacketScanner;
    #[cfg(feature = "sovereign")]
    use crate::plugins::privilege_escalation::certipy::CertipyScanner;
    #[cfg(feature = "sovereign")]
    use crate::plugins::exploitation::network::petitpotam::PetitPotamScanner;
    #[cfg(feature = "sovereign")]
    use crate::plugins::lateral_movement::sliver::SliverScanner;
    #[cfg(feature = "sovereign")]
    use crate::plugins::enumeration::cloud::scoutsuite::ScoutSuiteScanner;
    #[cfg(feature = "sovereign")]
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
    #[cfg(feature = "sovereign")]
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
    use crate::plugins::compliance::semgrep::SemgrepScanner;
    use crate::plugins::enumeration::web::oauth_security::OAuthScanner;
    use crate::plugins::enumeration::web::wcvs::WcvsScanner;
    use crate::plugins::exploitation::web::kxss::KxssScanner;
    use crate::plugins::exploitation::web::deserialization::DeserializationScanner;
    use crate::plugins::reconnaissance::passive::github_dorks::GitHubDorksScanner;
    use crate::plugins::exploitation::web::h2csmuggler::H2CSmugglerScanner;
    use crate::plugins::reconnaissance::active::cdncheck::CdnCheckScanner;
    use crate::plugins::reconnaissance::active::tlsx::TlsxScanner;
    use crate::plugins::enumeration::web::api::clairvoyance::ClairvoyanceScanner;
    use crate::plugins::exploitation::web::ghauri::GhauriScanner;
    use crate::plugins::exploitation::web::ssrfmap::SsrfmapScanner;
    use crate::plugins::exploitation::web::nosqlmap::NoSqlMapScanner;
    use crate::plugins::exploitation::web::gopherus::GopherusScanner;
    use crate::plugins::exploitation::web::cloud_metadata::CloudMetadataExtractor;
    #[cfg(feature = "sovereign")]
    use crate::plugins::reconnaissance::active::azurehound::AzureHoundScanner;
    #[cfg(feature = "sovereign")]
    use crate::plugins::reconnaissance::active::roadrecon::RoadReconScanner;
    use crate::plugins::exploitation::web::jwt_forge::JwtForgeScanner;
    use crate::plugins::enumeration::web::jwks_discovery::JwksDiscoveryScanner;
    use crate::plugins::intelligence::nvd_monitor::NvdMonitor;
    use crate::plugins::exploitation::web::cors_exfil::CorsTokenExfiltrator;
    use crate::plugins::verification::dns_verifier::DnsHijackVerifier;
    use crate::plugins::verification::secret_validator::SecretValidator;

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
        Box::new(KerbruteScanner::new()),
        Box::new(Enum4LinuxScanner::new()), 
        Box::new(NetExecScanner::new()), 
        Box::new(TruffleHogScanner::new()), 
        Box::new(DalfoxScanner::new()), 
        Box::new(KatanaScanner::new()), 
        #[cfg(feature = "sovereign")]
        Box::new(BloodHoundScanner::new(config.executor.clone(), config.correlation_engine.clone())), 
        #[cfg(feature = "sovereign")]
        Box::new(ResponderScanner::new()), 
        #[cfg(feature = "sovereign")]
        Box::new(crate::plugins::exploitation::network::sliver_automator::SliverAutomator::new()),
        #[cfg(feature = "sovereign")]
        Box::new(ImpacketScanner::new()), 
        #[cfg(feature = "sovereign")]
        Box::new(CertipyScanner::new()), 
        #[cfg(feature = "sovereign")]
        Box::new(PetitPotamScanner::new()), 
        #[cfg(feature = "sovereign")]
        Box::new(SliverScanner::new(config.executor.clone())), 
        #[cfg(feature = "sovereign")]
        Box::new(ScoutSuiteScanner::new()),
        #[cfg(feature = "sovereign")]
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
        Box::new(JwtToolScanner::new(config.insecure)), 
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
        #[cfg(feature = "sovereign")]
        Box::new(CoercerScanner::new()), 
        Box::new(CaidoScanner::new(&crate::utils::config::Config::from_env(), config.proxy_manager.clone())), 
        Box::new(JsluiceScanner::new()),
        Box::new(SubzyScanner::new()),
        Box::new(NoMore403Scanner::new(config.insecure)),
        Box::new(SmugglerScanner::new()),
        Box::new(GreyNoiseScanner::new()),
        Box::new(X8Scanner::new()),
        Box::new(InQLScanner::new()),
        Box::new(crate::plugins::compliance::syft::SyftScanner::new()),
        Box::new(crate::plugins::compliance::grype::GrypeScanner::new()),
        Box::new(crate::plugins::compliance::cosign::CosignScanner::new()),
        Box::new(PpmapScanner::new()),
        Box::new(CorsyScanner::new()),
        Box::new(WcdScanner::new()),
        Box::new(SsrfKingScanner::new(config.proxy_manager.clone())),
        Box::new(TplmapScanner::new()),
        Box::new(OpenRedirexScanner::new()),
        Box::new(LinkFinderScanner::new(&config)),
        Box::new(crate::plugins::enumeration::web::api::graphw00f::GraphW00fScanner::new()),
        Box::new(crate::plugins::enumeration::web::api::schemathesis::SchemathesisScanner::new()),
        Box::new(crate::plugins::enumeration::web::api::crackql::CrackqlScanner::new()),
        Box::new(SecretFinderScanner::new(&config)),
        Box::new(SubJSScanner::new()),
        Box::new(RetireScanner::new()),
        Box::new(SourceMapperScanner::new()),
        Box::new(UploadStrikeScanner::new(Some(config.proxy_manager.clone()))),
        Box::new(BusinessLogicScanner::new(Some(config.proxy_manager.clone()))),
        Box::new(SemgrepScanner::new()),
        Box::new(OAuthScanner::new()),
        Box::new(WcvsScanner::new()),
        Box::new(DeserializationScanner::new()),
        Box::new(GitHubDorksScanner::new(config.clone())),
        Box::new(H2CSmugglerScanner::new(config.clone())),
        Box::new(CdnCheckScanner::new()),
        Box::new(TlsxScanner::new()),
        Box::new(ClairvoyanceScanner::new(&config)),
        Box::new(GhauriScanner::new(&config)),
        Box::new(SsrfmapScanner::new(&config)),
        Box::new(NoSqlMapScanner::new(&config)),
        Box::new(GopherusScanner::new(&config)),
        Box::new(KxssScanner::new(&config)),
        Box::new(crate::plugins::enumeration::cloud::s3scanner::S3BucketScanner::new(&config)),
        Box::new(CloudMetadataExtractor::new()),
        #[cfg(feature = "sovereign")]
        Box::new(AzureHoundScanner::new()),
        #[cfg(feature = "sovereign")]
        Box::new(RoadReconScanner::new()),
        Box::new(NvdMonitor::new(std::env::var("NVD_API_KEY").ok())), 
        Box::new(JwtForgeScanner::new()),
        Box::new(JwksDiscoveryScanner::new()),
        Box::new(CorsTokenExfiltrator::new()),
        Box::new(DnsHijackVerifier::new()),
        Box::new(SecretValidator::new()),
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
        scanners.push(Box::new(crate::plugins::compliance::syft::SyftScanner::new()));
        scanners.push(Box::new(crate::plugins::compliance::grype::GrypeScanner::new()));
        scanners.push(Box::new(crate::plugins::compliance::cosign::CosignScanner::new()));
        scanners.push(Box::new(APKLeaksScanner::new(&config)));
        scanners.push(Box::new(ApktoolScanner::new()));
        scanners.push(Box::new(JadxScanner::new()));
        scanners.push(Box::new(DrozerScanner::new()));
        scanners.push(Box::new(FridaScanner::new()));
        scanners.push(Box::new(ObjectionScanner::new()));
        scanners.push(Box::new(MarianaTrenchScanner::new()));
        if let (Some(url), Some(key)) = (&config.mobsf_url, &config.mobsf_api_key) {
            if !key.is_empty() && !key.starts_with("YOUR_") && key.len() > 10 {
                scanners.push(Box::new(MobSFScanner::<M>::new(url.clone(), key.clone(), config.mobsf_timeout_secs)));
            } else {
                tracing::warn!("MobSF API Key is missing, empty or using placeholder. Skipping MobSFScanner.");
            }
        }
    }

    scanners
}
