use anyhow::{Context, Result};
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use tracing::{info, error, warn};
use futures::stream::StreamExt;

use crate::models::{TargetHost, TargetStatus};
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
    pub dashboard_port: Option<u16>,
    pub max_layer: ScanLayer,
}

pub struct RedTeamEngine {
    config: EngineConfig,
    shutdown_token: CancellationToken,
    memory_monitor: Arc<MemoryMonitor>,
    sandbox: Arc<SandboxDispatcher>,
    approval_gate: Arc<ApprovalGate>,
    proxy_manager: Arc<crate::utils::proxy::ProxyManager>,
}

impl RedTeamEngine {
    pub fn new(config: EngineConfig, soft_limit: usize, hard_limit: usize) -> Self {
        let shutdown_token = CancellationToken::new();
        let memory_monitor = Arc::new(MemoryMonitor::new(soft_limit as u32, hard_limit as u32));
        let res_mgr = SysResourceManager::new();
        let sandbox = Arc::new(SandboxDispatcher::new(res_mgr));
        let approval_gate = Arc::new(ApprovalGate::for_red_team());
        let proxy_manager = Arc::new(crate::utils::proxy::ProxyManager::new(
            config.proxies.clone().unwrap_or_default(),
            config.insecure
        ));
        
        Self {
            config,
            shutdown_token,
            memory_monitor,
            sandbox,
            approval_gate,
            proxy_manager,
        }
    }

    pub fn from_config(config: EngineConfig, utils_config: &crate::utils::config::Config) -> Self {
        let shutdown_token = CancellationToken::new();
        let memory_monitor = Arc::new(MemoryMonitor::new(
            utils_config.soft_memory_limit_mb as u32, 
            utils_config.hard_memory_limit_mb as u32
        ));
        let res_mgr = SysResourceManager::new();
        let sandbox = Arc::new(SandboxDispatcher::new(res_mgr));
        let approval_gate = Arc::new(ApprovalGate::for_red_team());
        let proxy_manager = Arc::new(crate::utils::proxy::ProxyManager::new(
            config.proxies.clone().unwrap_or_default(),
            config.insecure
        ));
        
        Self {
            config,
            shutdown_token,
            memory_monitor,
            sandbox,
            approval_gate,
            proxy_manager,
        }
    }

    pub async fn run_autopilot(
        &self, 
        mut target_hosts: futures::stream::BoxStream<'static, TargetHost>,
        sink: Box<dyn DataSink>
    ) -> Result<()> {
        info!("🤖 SENTINEL: Activating Autonomous Agent with Native AI Cascade...");
        
        let router = EngineFactory::build_default_router(self.config.ollama_url.clone())?;
        
        let mut builder = self.prepare_pipeline_builder(sink);
        let mut pipeline = builder.build()?;
        
        // Start standalone sink for Autonomous streaming
        let (sink_tx, sink_handle) = pipeline.start_sink_stage().await?;
        let pipeline_arc = Arc::new(pipeline);
        
        let agent = AutonomousAgent::new(
            router,
            pipeline_arc,
            self.approval_gate.clone(),
            Some(self.proxy_manager.clone())
        );

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

        let mut builder = self.prepare_pipeline_builder(sink);
        
        if swarm {
            let router = EngineFactory::build_default_router(self.config.ollama_url.clone())?;
            builder = builder.with_swarm(true, self.config.max_tokens, router, Some(self.proxy_manager.clone()));
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
        let do_client = Arc::new(DigitalOceanClient::new(do_token));
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
                
                // If we have no managed exits, provision one
                if pm.is_empty() {
                    info!("🚀 STEALTH: No exit nodes available. Provisioning new DigitalOcean droplet...");
                    match do_client.create_droplet("stealth-exit-01", "nyc1").await {
                        Ok(droplet) => {
                            info!("⏳ STEALTH: Waiting for droplet IP (Managed node ID: {})...", droplet.id);
                            match do_client.wait_for_ip(droplet.id).await {
                                Ok(ip) => {
                                    // Wait for cloud-init (danted) to finish (simple sleep for now)
                                    tokio::time::sleep(Duration::from_secs(60)).await;
                                    pm.add_managed_exit(ip);
                                }
                                Err(e) => error!("❌ STEALTH: Failed to get IP for droplet: {}", e),
                            }
                        }
                        Err(e) => error!("❌ STEALTH: Failed to create DO droplet: {}", e),
                    }
                }
                
                tokio::time::sleep(Duration::from_secs(300)).await;
            }
        });

        Ok(())
    }

    fn prepare_pipeline_builder(&self, sink: Box<dyn DataSink>) -> PipelineBuilder {
        let liveness_checker = LivenessChecker::new(self.config.dns_servers.clone(), self.config.doh);
        let jitter = Arc::new(crate::utils::common::HumanJitter::new(100, 1500));
        
        let proxy_manager = Some(self.proxy_manager.clone());

        let stealth_jitter = if self.config.stealth {
            Some(JitterSleep::for_stealth())
        } else {
            None
        };

        let policy = ScanLayerPolicy {
            max_layer: self.config.max_layer.clone(),
            require_approval_for_layer_3_plus: true, 
            require_approval_for_layer_4_plus: true,
            require_approval_for_layer_5: true,
        };

        let global_config = GlobalConfig {
            insecure: self.config.insecure,
            jitter: jitter.clone(),
            proxy_manager,
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
        };

        let mut builder = Pipeline::builder()
            .concurrency(self.config.concurrency)
            .shutdown_token(self.shutdown_token.clone())
            .liveness_checker(liveness_checker)
            .with_sink(sink)
            .with_jitter(stealth_jitter)
            .memory_monitor(self.memory_monitor.clone())
            .sandbox(self.sandbox.clone())
            .policy(policy)
            .approval_gate(self.approval_gate.clone());

        // Add discovery plugins
        for p in crate::plugins::get_all_discovery() {
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
}
