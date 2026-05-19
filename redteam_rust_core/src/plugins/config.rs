use std::sync::Arc;
use serde::{Deserialize, Serialize};
use crate::utils::executor::{StealthExecutor, ExecutorMode};

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

/// Global configuration shared across all plugins to ensure consistency and streamline initialization.
#[derive(Clone)]
pub struct GlobalConfig<M: ExecutorMode = crate::utils::executor::GhostMode> where M: Clone {
    pub insecure: bool,
    pub jitter: Arc<crate::utils::common::HumanJitter>,
    pub proxy_manager: Arc<crate::utils::proxy::ProxyManager>,
    pub nmap_options: NmapOptions,
    pub sandbox: Arc<crate::core::sandbox::SandboxDispatcher>,
    pub policy: Arc<dyn crate::core::policy::PolicyProvider>,
    pub executor: Arc<StealthExecutor<M>>,
    pub budget: Arc<crate::core::orchestrator::swarm::budget::TokenBudget>,
    pub correlation_engine: Arc<tokio::sync::Mutex<crate::core::correlation::CorrelationEngine>>,
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
    pub clairvoyance_wordlist_path: Option<String>,
    pub shuffledns_resolvers_path: Option<String>,
    pub shuffledns_wordlist_path: Option<String>,
    pub ssrfmap_path: Option<String>,
    pub nosqlmap_path: Option<String>,
    pub ghauri_path: Option<String>,
    pub gopherus_path: Option<String>,
    pub kxss_path: Option<String>,
    pub s3scanner_path: Option<String>,
    pub s3scanner_wordlist_path: Option<String>,
    pub shuffledns_path: Option<String>,
    pub massdns_path: Option<String>,
    pub sliver_ca_path: Option<String>,
    pub sliver_cert_path: Option<String>,
    pub sliver_key_path: Option<String>,
    pub sliver_server_addr: Option<String>,
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
        let policy = Arc::new(crate::core::policy::StaticPolicy::new());
        let proxy_manager = Arc::new(crate::utils::proxy::ProxyManager::new(
            Vec::new(),
            false,
            crate::utils::config::ProxyMode::Dante,
            0,
        ));
        let executor = Arc::new(StealthExecutor::new(
            policy.clone(),
            Some(proxy_manager.clone()),
            false,
        ));
        let res_mgr = crate::core::resource_manager::SysResourceManager::new();
        let sandbox = Arc::new(crate::core::sandbox::SandboxDispatcher::new(res_mgr).with_policy(policy.clone()));

        Self {
            insecure: false,
            jitter: Arc::new(crate::utils::common::HumanJitter::new(100, 1500)),
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
            budget: Arc::new(crate::core::orchestrator::swarm::budget::TokenBudget::new(50000)),
            correlation_engine: Arc::new(tokio::sync::Mutex::new(crate::core::correlation::CorrelationEngine::new())),
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
            nuclei_auto_update: true,
            h1_username: None,
            h1_api_key: None,
            bugcrowd_api_key: None,
            intigriti_token: None,
            bb_program_handle: None,
            clairvoyance_wordlist_path: None,
            shuffledns_resolvers_path: None,
            shuffledns_wordlist_path: None,
            ssrfmap_path: None,
            nosqlmap_path: None,
            ghauri_path: None,
            gopherus_path: None,
            kxss_path: None,
            s3scanner_path: None,
            s3scanner_wordlist_path: None,
            shuffledns_path: None,
            massdns_path: None,
            sliver_ca_path: None,
            sliver_cert_path: None,
            sliver_key_path: None,
            sliver_server_addr: None,
        }
    }
}
