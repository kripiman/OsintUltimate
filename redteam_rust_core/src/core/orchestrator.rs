use crate::models::{TargetHost, Finding, Severity, Category, TargetStatus, FINDING_PLUGIN_ERROR, FINDING_PLUGIN_PANIC};
use crate::plugins::ScannerPlugin;
use std::sync::Arc;
use futures::stream::StreamExt;
use tracing::{info, error, warn};
use crate::core::capability_layer::ScanLayerPolicy;
use crate::core::approval_gate::ApprovalGate;

pub struct Orchestrator {
    plugins: Arc<Vec<Box<dyn ScannerPlugin>>>,
    concurrency: usize,
    policy: ScanLayerPolicy,
    approval_gate: Arc<ApprovalGate>,
    blackarch_bridge: Arc<crate::core::blackarch::BlackArchBridge>,
    memory_semaphore: Arc<tokio::sync::Semaphore>,
    memory_monitor: Arc<crate::utils::memory_monitor::MemoryMonitor>,
    dashboard_tx: Option<tokio::sync::broadcast::Sender<Finding>>,
    dashboard_targets: Arc<dashmap::DashMap<String, TargetHost>>,
    swarm_mode: bool,
    max_tokens: u32,
    ai_router: Option<Arc<crate::core::ai::TieredAIRouter>>,
    sandbox: Arc<crate::core::sandbox::SandboxDispatcher>, // NUEVO
    proxy_manager: Option<Arc<crate::utils::proxy::ProxyManager>>,
}

impl Orchestrator {
    pub fn new(
        plugins: Arc<Vec<Box<dyn ScannerPlugin>>>,
        concurrency: usize,
        policy: ScanLayerPolicy,
        approval_gate: Arc<ApprovalGate>,
        blackarch_bridge: Arc<crate::core::blackarch::BlackArchBridge>,
        memory_monitor: Arc<crate::utils::memory_monitor::MemoryMonitor>,
        sandbox: Arc<crate::core::sandbox::SandboxDispatcher>,
    ) -> Self {
        let hard_limit = memory_monitor.hard_limit_mb();
        let memory_semaphore = Arc::new(tokio::sync::Semaphore::new(hard_limit as usize));

        Self {
            plugins,
            concurrency,
            policy,
            approval_gate,
            blackarch_bridge,
            memory_semaphore,
            memory_monitor,
            dashboard_tx: None,
            dashboard_targets: Arc::new(dashmap::DashMap::new()),
            swarm_mode: false,
            max_tokens: 0,
            ai_router: None,
            sandbox,
            proxy_manager: None,
        }
    }

    pub fn with_swarm_mode(mut self, enabled: bool, max_tokens: u32, router: Arc<crate::core::ai::TieredAIRouter>, proxy_manager: Option<Arc<crate::utils::proxy::ProxyManager>>) -> Self {
        self.swarm_mode = enabled;
        self.max_tokens = max_tokens;
        self.ai_router = Some(router);
        self.proxy_manager = proxy_manager;
        self
    }

    pub fn with_dashboard_preconfigured(&mut self, tx: tokio::sync::broadcast::Sender<Finding>, current_targets: Arc<dashmap::DashMap<String, TargetHost>>) {
        self.dashboard_tx = Some(tx);
        self.dashboard_targets = current_targets;
    }

    pub async fn run(
        self,
        input_rx: tokio::sync::mpsc::Receiver<TargetHost>,
        output_tx: tokio::sync::mpsc::Sender<TargetHost>,
        shutdown_token: tokio_util::sync::CancellationToken, 
    ) {
        info!("Orchestrator started. Concurrency: {}", self.concurrency);
        
        let available_ba_tools: Vec<String> = self.blackarch_bridge.get_available_tools()
            .iter().map(|t| t.name.clone()).collect();
        info!("BlackArch Intelligence: {} tools available ({}).", available_ba_tools.len(), available_ba_tools.join(", "));
        
        let plugins = self.plugins;

        let output_tx_clone = output_tx.clone();
        let stream = futures::stream::unfold((input_rx, shutdown_token.clone(), output_tx_clone), |(mut rx, token, out_tx)| async move {
            tokio::select! {
                val = rx.recv() => val.map(|t| (t, (rx, token, out_tx))),
                _ = token.cancelled() => {
                    // V10 FIX (HIGH-001): Drain rx explicitly to avoid discarding targets upon cancellation.
                    rx.close();
                    // AUDIT-005 FIX: Use recv() to ensure all buffered targets are processed after close()
                    while let Some(mut remaining_target) = rx.recv().await {
                        remaining_target.status = TargetStatus::Dead;
                        let mut findings = (*remaining_target.findings).clone();
                        findings.push(Finding::new(
                            "SHUTDOWN_ABORT",
                            Category::Availability,
                            Severity::Info,
                            "Target scan aborted due to graceful shutdown",
                            serde_json::json!({"host": remaining_target.host})
                        ));
                        remaining_target.findings = Arc::new(findings);
                        let _ = tokio::time::timeout(std::time::Duration::from_millis(100), out_tx.send(remaining_target)).await;
                    }
                    None // Graceful shutdown
                }
            }
        });

        tokio::pin!(stream);

        // Process concurrently up to `concurrency` limit
        let policy = self.policy;
        let approval_gate = self.approval_gate.clone();
        let blackarch_bridge = self.blackarch_bridge.clone();
        let memory_semaphore = self.memory_semaphore.clone();
        let memory_monitor = self.memory_monitor.clone();

        let dashboard_tx = self.dashboard_tx.clone();
        let dashboard_targets = self.dashboard_targets.clone();

        if self.swarm_mode {
            if let (Some(router), Some(out_tx)) = (self.ai_router.clone(), Some(output_tx.clone())) {
                info!("🐝 ORCHESTRATOR: Entering Swarm Mode (Max Tokens: {})", self.max_tokens);
                let pipeline = Arc::new(crate::core::pipeline::Pipeline::new_minimal(plugins.clone(), self.sandbox.clone()));
                let swarm = crate::core::swarm::SwarmOrchestrator::new(
                    router,
                    pipeline,
                    approval_gate.clone(),
                    self.max_tokens,
                    self.proxy_manager.clone(),
                );

                // Use buffered stream to run swarm on each target
                let swarm_stream = stream.map(move |target| {
                    let swarm = swarm.clone();
                    let out_tx = out_tx.clone();
                    async move {
                        let _ = swarm.run(target.clone(), out_tx).await;
                        target // Return original to keep stream moving if needed
                    }
                }).buffer_unordered(self.concurrency);

                tokio::pin!(swarm_stream);
                while let Some(_) = swarm_stream.next().await {}
                info!("🐝 ORCHESTRATOR: Swarm processing finished.");
                return;
            }
        }

        let mut processed_stream = stream.map(move |mut target| {
            let plugins = plugins.clone();
            let policy = policy;
            let approval_gate = approval_gate.clone();
            let blackarch_bridge = blackarch_bridge.clone();
            let memory_semaphore = memory_semaphore.clone();
            let memory_monitor = memory_monitor.clone();
            let dashboard_tx = dashboard_tx.clone();
            let dashboard_targets = dashboard_targets.clone();
            
            async move {
                // MEMORY-BACKPRESSURE: Wait if memory is critical 
                if memory_monitor.is_critical() {
                    warn!("MEMORY CRITICAL [{}MB]: Throttling scan for {}", memory_monitor.current_mb(), target.host);
                    while memory_monitor.is_critical() {
                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    }
                } else if memory_monitor.should_trigger_backpressure() {
                    // Soft throttle: small delay
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                }

                dashboard_targets.insert(target.host.clone(), target.clone());
                if let Some(ref tx) = dashboard_tx {
                    for f in target.findings.iter() {
                        let _ = tx.send(f.clone());
                    }
                }

                target.status = TargetStatus::Scanning;
                dashboard_targets.insert(target.host.clone(), target.clone());
                
                // QA-005 FIX: Use Arc only for read-only sharing. Collect findings via JoinSet return values.
                let target_ref = Arc::new(target);
                
                // CRIT-003 & HIGH-009 FIX: Parallel execution + Panic Isolation via tokio::spawn
                let mut join_set = tokio::task::JoinSet::new();
                for i in 0..plugins.len() {
                    let p = &plugins[i];
                    
                    // ARCH-EXT: Context-aware filtering
                    if p.metadata().target_type != target_ref.target_type {
                        continue;
                    }

                    let plugins_clone = Arc::clone(&plugins);
                    // Create a scan snapshot to avoid Arc contention on the full TargetHost
                    let target_snapshot = TargetHost {
                        host: target_ref.host.clone(),
                        ip: target_ref.ip.clone(),
                        resolved_ip: target_ref.resolved_ip.clone(),
                        target_type: target_ref.target_type,
                        status: TargetStatus::Scanning,
                        findings: Arc::new(Vec::new()),
                        tool_suggestions: Arc::new(Vec::new()),
                        tactical_context: Arc::clone(&target_ref.tactical_context),
                        extra_data: Arc::clone(&target_ref.extra_data),
                    };
                    let policy = policy;
                    let approval_gate = Arc::clone(&approval_gate);
                    let memory_semaphore_clone = memory_semaphore.clone();
                    let memory_monitor_clone = memory_monitor.clone();

                    join_set.spawn(async move {
                        let p = &plugins_clone[i];
                        let meta = p.metadata();
                        
                        if !policy.is_plugin_allowed(meta.layer) {
                            return (p.name().to_string(), Ok(Vec::new()));
                        }

                        if policy.needs_approval(meta.layer) {
                            if !approval_gate.is_approved(p.name()).await {
                                return (p.name().to_string(), Ok(Vec::new()));
                            }
                        }
                        
                        // ARCH-10: Dynamic Memory Permit Scaling
                        // If memory is tight, we increase the 'virtual cost' to throttle new heavy plugins.
                        let multiplier = if memory_monitor_clone.should_trigger_backpressure() {
                            2.0 
                        } else {
                            1.0
                        };
                        
                        let total_capacity = memory_monitor_clone.hard_limit_mb();
                        let base_permits = (meta.cost as u32).max(1) * (total_capacity / 10).max(10); // scale cost based on limit
                        let permits_needed = ((base_permits as f32 * multiplier) as u32).min(total_capacity.saturating_sub(1));
                        
                        let _permit = memory_semaphore_clone.acquire_many(permits_needed).await;
                        
                        match p.check_dependencies().await {
                            Ok(true) => (p.name().to_string(), p.scan(&target_snapshot).await),
                            Ok(false) => (p.name().to_string(), Ok(Vec::new())),
                            Err(e) => (p.name().to_string(), Err(e)),
                        }
                    });
                }

                // Collect all findings first via JoinSet results
                let mut all_findings = Vec::new();
                let mut plugin_error = false;

                while let Some(join_res) = join_set.join_next().await {
                    match join_res {
                        Ok((name, res)) => {
                            match res {
                                Ok(mut findings) => {
                                    all_findings.append(&mut findings);
                                }
                                Err(e) => {
                                    error!("Plugin {} error on {}: {}", name, target_ref.host, e);
                                    let mut error_findings = Vec::new(); // Local vec
                                    error_findings.push(Finding::new(
                                        FINDING_PLUGIN_ERROR,
                                        Category::Misconfiguration,
                                        Severity::Info, 
                                        &format!("Plugin {} failed", name),
                                        serde_json::json!({"error": e.to_string()})
                                    ));
                                    all_findings.append(&mut error_findings);
                                    plugin_error = true;
                                }
                            }
                        }
                        Err(join_err) => {
                            error!("Target task panicked: {}", join_err);
                            let mut panic_findings = Vec::new();
                            panic_findings.push(Finding::new(
                                FINDING_PLUGIN_PANIC,
                                Category::Misconfiguration,
                                Severity::Critical, 
                                "A scanner plugin panicked during execution!",
                                serde_json::json!({"error": join_err.to_string()})
                            ));
                            all_findings.append(&mut panic_findings);
                            plugin_error = true;
                        }
                    }
                }
                
                // QA-005 FIX: All tasks are done, so we are the only Arc holder.
                // Extract owned target and append findings directly — no clone needed.
                // QA-005 FIX: Attempt to extract owned target. Fallback to clone if other references exist (safe side).
                let mut target = Arc::try_unwrap(target_ref)
                    .unwrap_or_else(|arc| (*arc).clone());
                
                let mut findings = (*target.findings).clone();
                findings.append(&mut all_findings);
                target.findings = Arc::new(findings);
                // --- NEW: BlackArch Dynamic Tool Suggestion ---
                let mut suggestions = Vec::new();
                for finding in target.findings.iter() {
                    if finding.severity == Severity::High || finding.severity == Severity::Critical {
                        // Mapear categorías de hallazgos a capacidades
                        let capability = match finding.category {
                            Category::Vulnerability => Some(crate::plugins::Capability::VulnerabilityScanning),
                            Category::NetworkPort => Some(crate::plugins::Capability::ServiceDiscovery),
                            _ => None,
                        };

                        if let Some(cap) = capability {
                            let suggested = blackarch_bridge.suggest_tools_for_capability(cap);
                            for tool in suggested {
                                if !suggestions.contains(&tool.name) {
                                    suggestions.push(tool.name.clone());
                                }
                            }
                        }
                    }
                }

                if !suggestions.is_empty() {
                    let mut current_suggestions = (*target.tool_suggestions).clone();
                    current_suggestions.extend(suggestions);
                    target.tool_suggestions = Arc::new(current_suggestions);
                }

                if plugin_error {
                    target.status = TargetStatus::Error;
                }

                if target.status == TargetStatus::Scanning {
                     target.status = TargetStatus::Scanned;
                }

                if let Some(ref tx) = dashboard_tx {
                    for f in &all_findings {
                        let _ = tx.send(f.clone());
                    }
                }
                dashboard_targets.insert(target.host.clone(), target.clone());

                target
            }
        }).buffer_unordered(self.concurrency);

        while let Some(result) = processed_stream.next().await {
            if let Err(e) = output_tx.send(result).await {
                error!("Failed to send result to output channel: {}", e);
                break; // Downstream closed
            }
        }
        
        info!("Orchestrator finished processing.");
    }
}
