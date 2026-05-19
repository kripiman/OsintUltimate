use anyhow::{Context, Result};
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use tracing::{info, error};
use futures::stream::StreamExt;

use crate::models::TargetHost;
use crate::core::pipeline::{Pipeline, PipelineBuilder};
use crate::core::sink::DataSink;
use crate::core::factory::EngineFactory;
use crate::core::agent::AutonomousAgent;
use crate::core::approval_gate::ApprovalGate;
use crate::core::capability_layer::{ScanLayerPolicy, ScanLayer};
use crate::core::sandbox::SandboxDispatcher;
use crate::core::resource_manager::SysResourceManager;
use crate::utils::{LivenessChecker, MemoryMonitor, JitterSleep};
use crate::plugins::GlobalConfig;

#[derive(Clone)]
pub struct EngineConfig {
    pub concurrency: usize,
    pub ollama_url: String,
    pub max_tokens: u32,
    pub stealth: bool,
    pub insecure: bool,
    pub scripts: Option<String>,
    pub service_detection: bool,
    pub scan_type: String,
    pub fragment: bool,
    pub decoy: Option<String>,
    pub ports: Option<String>,
    pub vuln_scan: bool,
    pub dns_servers: Option<Vec<String>>,
    pub doh: bool,
    pub proxies: Option<Vec<String>>,
    pub plugins_dir: Option<String>,
    pub max_layer: ScanLayer,
    pub dashboard_port: Option<u16>,
    pub readiness_timeout: Duration, // V13: Configurable infrastructure wait
    pub proxy_mode: crate::utils::config::ProxyMode,
    pub proxy_pool_size: u32,
    pub mcp_token: Option<String>,
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
    pub dashboard_tx: Option<tokio::sync::broadcast::Sender<crate::models::Finding>>,
    pub dashboard_targets: Option<Arc<dashmap::DashMap<String, TargetHost>>>,
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
    pub workspace_dir: String,
}

use crate::utils::executor::{StealthExecutor, ExecutorMode};

pub struct RedTeamEngine<M: ExecutorMode = crate::utils::executor::GhostMode> {
    config: EngineConfig,
    shutdown_token: CancellationToken,
    memory_monitor: Arc<MemoryMonitor>,
    sandbox: Arc<SandboxDispatcher>,
    approval_gate: Arc<ApprovalGate>,
    proxy_manager: Arc<crate::utils::proxy::ProxyManager>,
    policy: Arc<crate::core::policy::ReloadablePolicy>,
    executor: Arc<StealthExecutor<M>>,
    correlation_engine: Arc<tokio::sync::Mutex<crate::core::correlation::CorrelationEngine>>,
}

impl RedTeamEngine<crate::utils::executor::GhostMode> {
    pub fn new(config: EngineConfig, soft_limit: usize, hard_limit: usize) -> Self {
        let shutdown_token = CancellationToken::new();
        let memory_monitor = Arc::new(MemoryMonitor::new(soft_limit as u32, hard_limit as u32));
        let res_mgr = SysResourceManager::new();
        let policy = Arc::new(crate::core::policy::ReloadablePolicy::new(None));
        let approval_gate = Arc::new(ApprovalGate::for_red_team());
        let proxy_manager = Arc::new(crate::utils::proxy::ProxyManager::new(
            config.proxies.clone().unwrap_or_default(),
            config.insecure,
            config.proxy_mode,
            config.proxy_pool_size,
        ));
        let sandbox = Arc::new(SandboxDispatcher::new(res_mgr)
            .with_policy(policy.clone())
            .with_proxy_manager(proxy_manager.clone()));

        let executor = Arc::new(crate::utils::executor::StealthExecutor::new(
            policy.clone(),
            Some(proxy_manager.clone()),
            config.stealth,
        ));
        
        let correlation_engine = Arc::new(tokio::sync::Mutex::new(crate::core::correlation::CorrelationEngine::new()));
        Self {
            config,
            shutdown_token,
            memory_monitor,
            sandbox,
            approval_gate,
            proxy_manager,
            policy,
            executor,
            correlation_engine,
        }
    }

    pub fn from_config(config: EngineConfig, utils_config: &crate::utils::config::Config) -> Self {
        let shutdown_token = CancellationToken::new();
        let correlation_engine = Arc::new(tokio::sync::Mutex::new(crate::core::correlation::CorrelationEngine::new()));
        let memory_monitor = Arc::new(MemoryMonitor::new(
            utils_config.soft_memory_limit_mb as u32, 
            utils_config.hard_memory_limit_mb as u32
        ));
        let res_mgr = SysResourceManager::new();
        let policy = Arc::new(crate::core::policy::ReloadablePolicy::new(utils_config.policy_file.as_deref()));
        let approval_gate = Arc::new(ApprovalGate::for_red_team());
        let proxy_manager = Arc::new(crate::utils::proxy::ProxyManager::new(
            config.proxies.clone().unwrap_or_default(),
            config.insecure,
            config.proxy_mode,
            config.proxy_pool_size,
        ));
        let sandbox = Arc::new(SandboxDispatcher::new(res_mgr)
            .with_policy(policy.clone())
            .with_proxy_manager(proxy_manager.clone()));

        let executor = Arc::new(crate::utils::executor::StealthExecutor::new(
            policy.clone(),
            Some(proxy_manager.clone()),
            config.stealth,
        ));
        
        Self {
            config,
            shutdown_token,
            memory_monitor,
            sandbox,
            approval_gate,
            proxy_manager,
            policy,
            executor,
            correlation_engine,
        }
    }
}

impl<M: ExecutorMode> RedTeamEngine<M> {
    pub async fn run_autopilot(
        &self, 
        mut target_hosts: futures::stream::BoxStream<'static, TargetHost>,
        sink: Box<dyn DataSink>
    ) -> Result<()> {
        info!("🤖 SENTINEL: Activating Autonomous Agent with Native AI Cascade...");
        
        let router = EngineFactory::build_default_router(self.config.ollama_url.clone(), self.proxy_manager.clone())?;
        
        // V13: Readiness Gate - Prevent OPSEC leak by waiting for stealth readiness
        if self.config.stealth {
            self.proxy_manager.wait_for_readiness(self.config.readiness_timeout).await
                .context(format!("Failed to establish stealth infrastructure readiness within {:?}", self.config.readiness_timeout))?;
        }

        // Phase 3: Initialize ActivityLog
        let timeline_path = std::path::PathBuf::from(&self.config.workspace_dir).join("timeline.jsonl");
        let activity_log = Arc::new(crate::utils::activity_log::ActivityLog::new(timeline_path).await?);
        
        // Add TimelineSink and BugBountyDraftSink to the pipeline
        let mut multi_sink = crate::core::sink::MultiSink::new();
        multi_sink.add(sink);
        multi_sink.add(Box::new(crate::core::sink::TimelineSink::new(activity_log.clone())));
        
        // V14 Phase 1: Repro-Proof Generator Drafts
        multi_sink.add(Box::new(crate::core::sink::BugBountyDraftSink::new(std::path::PathBuf::from(&self.config.workspace_dir)).await));
        
        let builder = self.prepare_pipeline_builder(Box::new(multi_sink));
        let mut pipeline = builder.build()?;
        
        // Start standalone sink for Autonomous streaming
        let (sink_tx, sink_handle) = pipeline.start_sink_stage().await?;
        let pipeline_arc = Arc::new(pipeline);
        
        let agent = AutonomousAgent::new(
            router,
            pipeline_arc,
            self.approval_gate.clone(),
            Some(self.proxy_manager.clone()),
            self.executor.clone(),
            self.policy.clone(),
        ).with_activity_log(activity_log);

        while let Some(target) = target_hosts.next().await {
            if let Err(e) = agent.run_autopilot(target, sink_tx.clone()).await {
                error!("Autonomous agent failed on target: {}", e);
            }
        }

        drop(sink_tx);
        let _ = sink_handle.await;
        Ok(())
    }

    pub async fn run_pipeline(
        &self, 
        target_hosts: futures::stream::BoxStream<'static, TargetHost>,
        sink: Box<dyn DataSink>,
        swarm: bool
    ) -> Result<()> {
        if swarm {
            info!("🐝 SWARM: Multi-Agent Enjambre mode activated.");
        }

        // V14 Phase 1: Wrap sink in MultiSink to include BugBountyDraftSink
        let mut multi_sink = crate::core::sink::MultiSink::new();
        multi_sink.add(sink);
        multi_sink.add(Box::new(crate::core::sink::BugBountyDraftSink::new(std::path::PathBuf::from(&self.config.workspace_dir)).await));

        let mut builder = self.prepare_pipeline_builder(Box::new(multi_sink));
        
        // V13: Readiness Gate - Prevent OPSEC leak by waiting for stealth readiness
        if self.config.stealth {
            self.proxy_manager.wait_for_readiness(self.config.readiness_timeout).await
                .context(format!("Failed to establish stealth infrastructure readiness within {:?}", self.config.readiness_timeout))?;
        }

        if swarm {
            let router = EngineFactory::build_default_router(self.config.ollama_url.clone(), self.proxy_manager.clone())?;
            builder = builder.with_swarm(true, self.config.max_tokens, router, Some(self.proxy_manager.clone()), self.executor.clone(), self.policy.clone());
        }

        let pipeline = builder.build()?;
        pipeline.run(target_hosts).await?;
        
        Ok(())
    }

    /// V13: Orchestrates the stealth infrastructure by provisioning DO exits when on Oracle.
    pub async fn init_stealth_infrastructure(&self, do_token: String) -> Result<()> {
        use crate::utils::stealth_detect::is_oracle_cloud;
        use crate::infrastructure::digital_ocean::DigitalOceanClient;
        
        let is_oracle = is_oracle_cloud().await || self.config.stealth;
        if !is_oracle {
            return Ok(());
        }

        info!("🛡️ V13: Stealth Mode Active. Ensuring DigitalOcean exit nodes...");
        let do_client = Arc::new(DigitalOceanClient::new(do_token, self.proxy_manager.clone()));
        let pm = self.proxy_manager.clone();
        let shutdown = self.shutdown_token.clone();

        // Resume existing droplets with osint-ultimate tag
        if let Ok(existing) = do_client.list_droplets().await {
            for d in existing {
                if let Some(ip) = d.public_ip() {
                    pm.add_managed_exit(ip);
                }
            }
        }

        // Provisioning Task: Ensure at least one DO exit node is always available
        tokio::spawn(async move {
            loop {
                if shutdown.is_cancelled() { break; }
                
                // V14.1 High-Speed Egress: Maintain the Pre-Warmed Pool
                let current_exits = pm.get_managed_exits().len();
                let pool_size = pm.proxy_pool_size as usize;
                
                if current_exits < pool_size || (current_exits == 0 && pool_size == 0) {
                    let mode = pm.proxy_mode;
                    let target = if pool_size == 0 { 1 } else { pool_size };
                    info!("🚀 STEALTH: Maintaining pool (Current: {}, Target: {}). Provisioning new DigitalOcean droplet (nyc1) in mode {:?}...", current_exits, target, mode);
                    match do_client.create_droplet(&format!("stealth-exit-{:x}", rand::random::<u32>()), "nyc1", mode).await {
                        Ok(droplet) => {
                            info!("⏳ STEALTH: Waiting for droplet IP (Managed node ID: {})...", droplet.id);
                            match do_client.wait_for_ip(droplet.id).await {
                                Ok(ip) => {
                                    let mut ready = false;
                                    let user = droplet.socks_user.as_deref().unwrap_or("operator");
                                    let pass = droplet.socks_pass.as_deref().unwrap_or("");
                                    
                                    info!("⏳ STEALTH: Provisioned IP {}. Validating professional SOCKS5 auth ({})...", ip, user);
                                    
                                    for _ in 0..15 { 
                                        // Health check: Can we connect?
                                        if let Ok(Ok(_)) = tokio::time::timeout(Duration::from_secs(2), tokio::net::TcpStream::connect(format!("{}:1080", ip))).await {
                                            ready = true;
                                            break;
                                        }
                                        tokio::time::sleep(Duration::from_secs(2)).await;
                                    }
 
                                    if ready {
                                        pm.add_managed_exit_with_auth(ip, user, pass);
                                    } else {
                                        error!("❌ STEALTH: Droplet {} IP ready but SOCKS5 (danted) failed to start. Destroying.", ip);
                                        let _ = do_client.destroy_droplet(droplet.id).await;
                                    }
                                }
                                Err(e) => error!("❌ STEALTH: Failed to get IP for droplet: {}", e),
                            }
                        }
                        Err(e) => error!("❌ STEALTH: Failed to create DO droplet: {}", e),
                    }
                }
                
                tokio::time::sleep(Duration::from_secs(60)).await; // Faster check while provisioning
            }
        });

        Ok(())
    }
    fn build_global_config(&self, jitter: Arc<crate::utils::common::HumanJitter>) -> GlobalConfig<M> {
        GlobalConfig {
            insecure: self.config.insecure,
            jitter,
            proxy_manager: self.proxy_manager.clone(),
            nmap_options: crate::plugins::NmapOptions {
                scripts: self.config.scripts.clone(),
                stealth: self.config.stealth,
                service_detection: self.config.service_detection,
                scan_type: self.config.scan_type.clone(),
                fragment: self.config.fragment,
                decoy: self.config.decoy.clone(),
                ports: self.config.ports.clone(),
                vuln_scan: self.config.vuln_scan,
            },
            sandbox: self.sandbox.clone(),
            policy: self.policy.clone(),
            executor: self.executor.clone(),
            budget: Arc::new(crate::core::orchestrator::swarm::budget::TokenBudget::new(self.config.max_tokens)),
            correlation_engine: self.correlation_engine.clone(),
            mcp_token: self.config.mcp_token.clone(),
            nuclei_tags: crate::utils::config::Config::from_env().nuclei_tags,
            nuclei_severity: crate::utils::config::Config::from_env().nuclei_severity,
            nuclei_custom_templates: crate::utils::config::Config::from_env().nuclei_custom_templates,
            mobsf_url: self.config.mobsf_url.clone(),
            mobsf_api_key: self.config.mobsf_api_key.clone(),
            mobsf_timeout_secs: self.config.mobsf_timeout_secs,
            vigil_url: self.config.vigil_url.clone(),
            vigil_api_key: self.config.vigil_api_key.clone(),
            rebuff_url: self.config.rebuff_url.clone(),
            rebuff_api_token: self.config.rebuff_api_token.clone(),
            policy_file: self.config.policy_file.clone(),
            strict_scope: self.config.strict_scope,
            nuclei_auto_update: self.config.nuclei_auto_update,
            h1_username: self.config.h1_username.clone(),
            h1_api_key: self.config.h1_api_key.clone(),
            bugcrowd_api_key: self.config.bugcrowd_api_key.clone(),
            intigriti_token: self.config.intigriti_token.clone(),
            bb_program_handle: self.config.bb_program_handle.clone(),
            clairvoyance_wordlist_path: self.config.clairvoyance_wordlist_path.clone(),
            shuffledns_resolvers_path: self.config.shuffledns_resolvers_path.clone(),
            shuffledns_wordlist_path: self.config.shuffledns_wordlist_path.clone(),
            ssrfmap_path: self.config.ssrfmap_path.clone(),
            nosqlmap_path: self.config.nosqlmap_path.clone(),
            ghauri_path: self.config.ghauri_path.clone(),
            gopherus_path: self.config.gopherus_path.clone(),
            kxss_path: self.config.kxss_path.clone(),
            s3scanner_path: self.config.s3scanner_path.clone(),
            s3scanner_wordlist_path: self.config.s3scanner_wordlist_path.clone(),
            shuffledns_path: self.config.shuffledns_path.clone(),
            massdns_path: self.config.massdns_path.clone(),
            sliver_ca_path: self.config.sliver_ca_path.clone(),
            sliver_cert_path: self.config.sliver_cert_path.clone(),
            sliver_key_path: self.config.sliver_key_path.clone(),
            sliver_server_addr: self.config.sliver_server_addr.clone(),
            stealth_policy: crate::plugins::detection_evasion::stealth_policy::StealthPolicy::default(),
        }
    }

    fn build_pipeline_builder_from(
        &self,
        liveness_checker: LivenessChecker,
        stealth_jitter: Option<JitterSleep>,
        policy: ScanLayerPolicy,
        sink: Box<dyn DataSink>,
    ) -> PipelineBuilder<M> {
        Pipeline::builder()
            .concurrency(self.config.concurrency)
            .shutdown_token(self.shutdown_token.clone())
            .liveness_checker(liveness_checker)
            .with_sink(sink)
            .with_jitter(stealth_jitter)
            .memory_monitor(self.memory_monitor.clone())
            .sandbox(self.sandbox.clone())
            .layer_policy(policy)
            .approval_gate(self.approval_gate.clone())
            .with_policy(self.policy.clone())
            .with_executor(self.executor.clone())
            .strict_scope(self.config.strict_scope)
    }

    fn prepare_pipeline_builder(&self, sink: Box<dyn DataSink>) -> PipelineBuilder<M> {
        let liveness_checker = LivenessChecker::new_with_proxy(
            self.config.dns_servers.clone(), 
            self.config.doh, 
            Some(self.proxy_manager.clone())
        );
        let jitter = Arc::new(crate::utils::common::HumanJitter::new(100, 1500));
        
        let stealth_jitter = if self.config.stealth {
            Some(JitterSleep::for_stealth())
        } else {
            None
        };

        let policy = ScanLayerPolicy {
            max_layer: self.config.max_layer,
            require_approval_for_layer_3_plus: true, 
            require_approval_for_layer_4_plus: true,
            require_approval_for_layer_5: true,
        };

        let global_config = self.build_global_config(jitter);
        let mut builder = self.build_pipeline_builder_from(liveness_checker, stealth_jitter, policy, sink);

        // Add discovery plugins
        for p in crate::plugins::get_all_discovery(global_config.clone()) {
            builder = builder.with_discovery(p);
        }

        // Add scanner plugins
        for p in crate::plugins::get_all_scanners(global_config) {
            builder = builder.with_plugin(p);
        }

        // Add dynamic plugins if directory provided
        if let Some(ref dir) = self.config.plugins_dir {
            let mut loader = crate::core::plugin_loader::DynamicPluginLoader::new();
            if let Ok(dynamic_plugins) = loader.load_plugins_from_dir(std::path::Path::new(dir)) {
                for plugin in dynamic_plugins {
                    builder = builder.with_plugin(plugin);
                }
            }
        }

        if let (Some(tx), Some(targets)) = (&self.config.dashboard_tx, &self.config.dashboard_targets) {
            builder = builder.with_dashboard(tx.clone(), targets.clone());
        }

        builder
    }

    pub fn shutdown_token(&self) -> CancellationToken {
        self.shutdown_token.clone()
    }
    
    pub fn memory_monitor(&self) -> Arc<MemoryMonitor> {
        self.memory_monitor.clone()
    }

    pub fn approval_gate(&self) -> Arc<ApprovalGate> {
        self.approval_gate.clone()
    }

    pub fn proxy_manager(&self) -> Arc<crate::utils::proxy::ProxyManager> {
        self.proxy_manager.clone()
    }

    pub fn policy(&self) -> Arc<crate::core::policy::ReloadablePolicy> {
        self.policy.clone()
    }
}
