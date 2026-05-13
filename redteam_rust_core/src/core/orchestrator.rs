use crate::models::{TargetHost, Finding, Severity, Category, TargetStatus, FINDING_PLUGIN_ERROR, FINDING_PLUGIN_PANIC};
use crate::models::constants::*;
use dashmap::DashSet;
use crate::plugins::{ScannerPlugin, Capability};
use std::sync::Arc;
use futures::stream::StreamExt;
use tracing::{info, error, warn};
use crate::core::capability_layer::ScanLayerPolicy;
use crate::core::approval_gate::ApprovalGate;
use crate::utils::executor::{StealthExecutor, ExecutorMode};

pub struct Orchestrator<M: ExecutorMode> {
    plugins: Arc<Vec<Box<dyn ScannerPlugin>>>,
    concurrency: usize,
    layer_policy: ScanLayerPolicy,
    approval_gate: Arc<ApprovalGate>,
    blackarch_bridge: Arc<crate::core::blackarch::BlackArchBridge>,
    memory_semaphore: Arc<tokio::sync::Semaphore>,
    memory_monitor: Arc<crate::utils::memory_monitor::MemoryMonitor>,
    dashboard_tx: Option<tokio::sync::broadcast::Sender<Finding>>,
    dashboard_targets: Arc<dashmap::DashMap<String, TargetHost>>,
    swarm_mode: bool,
    max_tokens: u32,
    ai_router: Option<Arc<crate::core::ai::TieredAIRouter>>,
    sandbox: Arc<crate::core::sandbox::SandboxDispatcher>,
    proxy_manager: Option<Arc<crate::utils::proxy::ProxyManager>>,
    policy: Arc<dyn crate::core::policy::PolicyProvider>,
    executor: Arc<StealthExecutor<M>>,
    strict_scope: bool,
    db_pool: Option<sqlx::PgPool>,
    current_scan_id: Option<i64>,
    inventory: Arc<crate::core::swarm::inventory::SwarmInventory>,
    sliver_ca_path: Option<String>,
    sliver_cert_path: Option<String>,
    sliver_key_path: Option<String>,
    sliver_server_addr: Option<String>,
}

pub struct OrchestratorConfig<M: ExecutorMode> {
    pub plugins: Arc<Vec<Box<dyn ScannerPlugin>>>,
    pub concurrency: usize,
    pub layer_policy: ScanLayerPolicy,
    pub approval_gate: Arc<ApprovalGate>,
    pub blackarch_bridge: Arc<crate::core::blackarch::BlackArchBridge>,
    pub memory_monitor: Arc<crate::utils::memory_monitor::MemoryMonitor>,
    pub sandbox: Arc<crate::core::sandbox::SandboxDispatcher>,
    pub policy: Arc<dyn crate::core::policy::PolicyProvider>,
    pub executor: Arc<StealthExecutor<M>>,
    pub strict_scope: bool,
    pub feedback_tx: Option<tokio::sync::mpsc::Sender<TargetHost>>,
    pub db_pool: Option<sqlx::PgPool>,
    pub current_scan_id: Option<i64>,
    pub inventory: Option<Arc<crate::core::swarm::inventory::SwarmInventory>>,
    pub sliver_ca_path: Option<String>,
    pub sliver_cert_path: Option<String>,
    pub sliver_key_path: Option<String>,
    pub sliver_server_addr: Option<String>,
}

impl<M: ExecutorMode> Orchestrator<M> {
    pub fn new(config: OrchestratorConfig<M>) -> Self {
        let hard_limit = config.memory_monitor.hard_limit_mb();
        let memory_semaphore = Arc::new(tokio::sync::Semaphore::new(hard_limit as usize));

        if let Some(feedback_tx) = &config.feedback_tx {
            for scanner in config.plugins.iter() {
                scanner.set_feedback_channel(feedback_tx.clone());
            }
        }

        Self {
            plugins: config.plugins,
            concurrency: config.concurrency,
            layer_policy: config.layer_policy,
            approval_gate: config.approval_gate,
            blackarch_bridge: config.blackarch_bridge,
            memory_semaphore,
            memory_monitor: config.memory_monitor,
            dashboard_tx: None,
            dashboard_targets: Arc::new(dashmap::DashMap::new()),
            swarm_mode: false,
            max_tokens: 0,
            ai_router: None,
            sandbox: config.sandbox,
            proxy_manager: None,
            policy: config.policy,
            executor: config.executor,
            strict_scope: config.strict_scope,
            db_pool: config.db_pool,
            current_scan_id: config.current_scan_id,
            inventory: config.inventory.unwrap_or_else(|| Arc::new(crate::core::swarm::inventory::SwarmInventory::new())),
            sliver_ca_path: config.sliver_ca_path,
            sliver_cert_path: config.sliver_cert_path,
            sliver_key_path: config.sliver_key_path,
            sliver_server_addr: config.sliver_server_addr,
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
        
        // --- PHASE 5.1: MONITOR LIFECYCLE ---
        let plugins_for_monitor = self.plugins.clone();
        let dashboard_tx_for_monitor = self.dashboard_tx.clone();
        let shutdown_token_for_monitor = shutdown_token.clone();

        // --- PHASE 5.5: SLIVER FEEDBACK LOOP ---
        if let Some(addr) = &self.sliver_server_addr {
            let ca = self.sliver_ca_path.as_ref().and_then(|p| std::fs::read(p).ok());
            let cert = self.sliver_cert_path.as_ref().and_then(|p| std::fs::read(p).ok());
            let key = self.sliver_key_path.as_ref().and_then(|p| std::fs::read(p).ok());
            
            let feedback_loop = crate::core::c2::sliver_feedback::SliverFeedbackLoop::new(
                addr.clone(),
                self.inventory.clone(),
                ca,
                cert,
                key
            );
            
            tokio::spawn(async move {
                if let Err(e) = feedback_loop.run().await {
                    error!("🚨 V15.5 C2_FEEDBACK: Sliver feedback loop terminated with error: {}", e);
                }
            });
        }
        
        tokio::spawn(async move {
            info!("🛡️  V15.1 MONITOR: Starting lifecycle watcher loop.");
            let mut restart_counts = std::collections::HashMap::new();
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        for p in plugins_for_monitor.iter() {
                            if p.metadata().is_monitor {
                                match p.poll_status().await {
                                    Ok(crate::plugins::PluginStatus::Crashed(reason)) => {
                                        let count = restart_counts.entry(p.name().to_string()).or_insert(0);
                                        if *count < 3 {
                                            warn!("🔄 V15.1 MONITOR: Plugin '{}' crashed ({}). Restarting (Attempt {}/3)...", p.name(), reason, *count + 1);
                                            *count += 1;
                                            
                                            // V15.2 FIX: Cleanup before restart to avoid port conflicts (I.e. Responder)
                                            if let Err(e) = p.stop().await {
                                                error!("❌ V15.1 MONITOR: Failed to stop/cleanup plugin '{}': {}", p.name(), e);
                                            }
                                            
                                            // Re-scan trigger (Note: Real implementation would depends on how the plugin handles target state)
                                        } else {
                                            error!("🚨 V15.1 MONITOR: Plugin '{}' failed 3 times. SUSPENDING.", p.name());
                                            if let Some(ref tx) = dashboard_tx_for_monitor {
                                                let _ = tx.send(Finding::new(
                                                    "MONITOR_FAILURE",
                                                    Category::Availability,
                                                    Severity::Critical,
                                                    &format!("Plugin {} suspended after 3 crashes", p.name()),
                                                    serde_json::json!({"reason": reason, "plugin": p.name()})
                                                ));
                                            }
                                        }
                                    }
                                    Ok(_) => {
                                        // Reset count on healthy status
                                        restart_counts.insert(p.name().to_string(), 0);
                                    }
                                    Err(e) => {
                                        error!("❌ V15.1 MONITOR: Error polling status for {}: {}", p.name(), e);
                                    }
                                }
                            }
                        }
                    }
                    _ = shutdown_token_for_monitor.cancelled() => {
                        info!("🛡️  V15.1 MONITOR: Shutdown signal received. Stopping watcher.");
                        break;
                    }
                }
            }
        });
        
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
                        remaining_target.version += 1;
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
        let lp = self.layer_policy;
        let policy = self.policy.clone();
        let approval_gate = self.approval_gate.clone();
        let blackarch_bridge = self.blackarch_bridge.clone();
        let memory_semaphore = self.memory_semaphore.clone();
        let memory_monitor = self.memory_monitor.clone();

        let dashboard_tx = self.dashboard_tx.clone();
        let dashboard_targets = self.dashboard_targets.clone();
        let inventory = self.inventory.clone();

        match (self.swarm_mode, self.ai_router.clone(), Some(output_tx.clone())) {
            (true, Some(router), Some(out_tx)) => {
                info!("🐝 ORCHESTRATOR: Entering Swarm Mode (Max Tokens: {})", self.max_tokens);
                let pipeline = Arc::new(crate::core::pipeline::Pipeline::new_minimal(plugins.clone(), self.sandbox.clone(), None, None));
                let swarm = crate::core::swarm::SwarmOrchestrator::new(crate::core::swarm::SwarmConfig {
                    router,
                    pipeline,
                    approval_gate: approval_gate.clone(),
                    max_tokens: self.max_tokens,
                    proxy_manager: self.proxy_manager.clone(),
                    executor: self.executor.clone(),
                    policy: self.policy.clone(),
                });

                let swarm_stream = stream.map(move |target| {
                    let swarm = swarm.clone();
                    let out_tx = out_tx.clone();
                    async move {
                        let _ = swarm.run(target.clone(), out_tx).await;
                        target
                    }
                }).buffer_unordered(self.concurrency);

                tokio::pin!(swarm_stream);
                while swarm_stream.next().await.is_some() {}
                info!("🐝 ORCHESTRATOR: Swarm processing finished.");
            }
            _ => {
                let mut processed_stream = stream.map(move |target| {
                    let mut target = target; 
                    let plugins = plugins.clone();
                    let lp = lp;
                    let policy = policy.clone();
                    let strict_scope = self.strict_scope; // Assuming strict_scope is available in self or we pass it
                    let approval_gate = approval_gate.clone();
                    let blackarch_bridge = blackarch_bridge.clone();
                    let memory_semaphore = memory_semaphore.clone();
                    let memory_monitor = memory_monitor.clone();
                    let dashboard_tx = dashboard_tx.clone();
                    let dashboard_targets = dashboard_targets.clone();
                    let inventory = inventory.clone();
                    
                    async move {
                // V14.2 SCOPE ENFORCEMENT: Fail-Closed Check
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
                        return target;
                    } else {
                        info!("🛡️ V14.2 SCOPE: Target '{}' is out of scope but strict_scope is DISABLED. Proceeding with caution.", target.host);
                    }
                }

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
                target.version += 1;
                dashboard_targets.insert(target.host.clone(), target.clone());
                
                // QA-005 FIX: Use Arc only for read-only sharing. Collect findings via JoinSet return values.
                let target_ref = Arc::new(target);
                
                // CRIT-003 & HIGH-009 FIX: Parallel execution + Panic Isolation via tokio::spawn
                let mut join_set = tokio::task::JoinSet::new();

                // V14.6: Extract priority_plugins from tactical_context for two-round spawn
                let priority_set: std::collections::HashSet<String> = target_ref.tactical_context
                    .get("priority_plugins")
                    .and_then(|v| v.as_array())
                    .map(|arr| arr.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect())
                    .unwrap_or_default();

                // Two-round spawn: pass=true → priority plugins first, pass=false → rest
                // Both rounds are parallel within the same JoinSet (no await between rounds)
                for pass in [true, false] {
                for i in 0..plugins.len() {
                    let p = &plugins[i];
                    let is_priority = priority_set.contains(p.name());
                    if pass != is_priority { continue; }
                    
                    // ARCH-EXT: Context-aware filtering
                    if p.metadata().target_type != target_ref.target_type {
                        continue;
                    }

                    // CDN GATING (V14.5): Skip heavy tools for targets behind CDN/WAF
                    if target_ref.skip_heavy_scan {
                        let meta = p.metadata();
                        let is_heavy = meta.capabilities.contains(&Capability::VulnerabilityScanning) || 
                                       meta.capabilities.contains(&Capability::WebFuzzing);
                        if is_heavy {
                            info!("🛡️ CDN GATE: Skipping heavy scan tool '{}' for {}", p.name(), target_ref.host);
                            continue;
                        }
                    }

                    let plugins_clone = Arc::clone(&plugins);
                    // Create a scan snapshot to avoid Arc contention on the full TargetHost
                    let target_snapshot = TargetHost {
                        host: target_ref.host.clone(),
                        ip: target_ref.ip.clone(),
                        resolved_ip: target_ref.resolved_ip.clone(),
                        target_type: target_ref.target_type,
                        file_path: target_ref.file_path.clone(),
                        user: target_ref.user.clone(),
                        status: TargetStatus::Scanning,
                        findings: Arc::new(Vec::new()),
                        tool_suggestions: Arc::new(Vec::new()),
                        tactical_context: Arc::clone(&target_ref.tactical_context),
                        extra_data: Arc::clone(&target_ref.extra_data),
                        version: target_ref.version,
                        skip_heavy_scan: target_ref.skip_heavy_scan,
                        scan_id: target_ref.scan_id,
                        scope_id: target_ref.scope_id.clone(),
                    };
                    let lp = lp;
                    let approval_gate = Arc::clone(&approval_gate);
                    let memory_semaphore_clone = memory_semaphore.clone();
                    let memory_monitor_clone = memory_monitor.clone();

                    join_set.spawn(async move {
                        let p = &plugins_clone[i];
                        let meta = p.metadata();
                        
                        if !lp.is_plugin_allowed(meta.layer) {
                            return (p.name().to_string(), Ok(Vec::new()));
                        }

                        if lp.needs_approval(meta.layer)
                            && !approval_gate.is_approved(p.name()).await {
                                return (p.name().to_string(), Ok(Vec::new()));
                            }
                        
                        // ARCH-10: Dynamic Memory Permit Scaling
                        // If memory is tight, we increase the 'virtual cost' to throttle new heavy plugins.
                        let multiplier = if memory_monitor_clone.should_trigger_backpressure() {
                            2.0 
                        } else {
                            1.0
                        };
                        
                        let total_capacity = memory_monitor_clone.hard_limit_mb();
                        let base_permits = meta.cost.max(1) * (total_capacity / 10).max(10); // scale cost based on limit
                        let permits_needed = ((base_permits as f32 * multiplier) as u32).min(total_capacity.saturating_sub(1));
                        
                        let _permit = memory_semaphore_clone.acquire_many(permits_needed).await;
                        
                        match p.check_dependencies().await {
                            Ok(true) => (p.name().to_string(), p.scan(&target_snapshot).await),
                            Ok(false) => (p.name().to_string(), Ok(Vec::new())),
                            Err(e) => (p.name().to_string(), Err(e)),
                        }
                    });
                }
                } // end for pass (V14.6 two-round priority spawn)

                // Collect all findings first via JoinSet results
                let mut all_findings = Vec::new();
                let mut plugin_error = false;

                while let Some(join_res) = join_set.join_next().await {
                    match join_res {
                        Ok((name, res)) => {
                            match res {
                                Ok(mut findings) => {
                                    for f in findings.iter_mut() {
                                        if f.core.source_plugin.is_none() {
                                            f.core.source_plugin = Some(name.clone());
                                        }
                                        f.core.scope_id = target_ref.scope_id.clone();
                                    }
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
                
                info!("🔱 ORCHESTRATOR: Swarm processing finished for {}. Findings: {}", target_ref.host, all_findings.len());

                // QA-005 FIX: Remove from dashboard_targets temporarily to drop the Arc reference count.
                // This allows Arc::try_unwrap to succeed and gives us unique ownership without deep cloning.
                dashboard_targets.remove(&target_ref.host);

                let mut target = Arc::try_unwrap(target_ref)
                    .unwrap_or_else(|arc| (*arc).clone());
                
                if !all_findings.is_empty() {
                    let fired_chains: DashSet<String> = DashSet::new();

                    // --- PHASE 5.3: FAST-PATH INGESTION (NTLM TIMING) ---
                    // We ingest credentials BEFORE evaluating rules to ensure 
                    // that NetExec/Spray triggers can immediately use fresh hashes.
                    for f in &all_findings {
                        inventory.ingest_finding(f.clone(), crate::core::swarm::inventory::TrustLevel::Private);
                    }

                    // --- NEW: REACTIVE RULE ENGINE (CHAINS 1-10) ---
                    let rules = crate::core::reactive_engine::get_all_rules();
                    let mut extra_findings = crate::core::reactive_engine::evaluate(
                        &rules, &all_findings, &target,
                        &plugins, &self.layer_policy, &approval_gate, &fired_chains,
                        Some(&inventory),
                    ).await;

                    // --- REACTIVE TRIGGER: SSRF -> CLOUD METADATA ---
                    let ssrf_hit = all_findings.iter().find(|f| f.core.id == FINDING_SSRF).cloned();
                    if let Some(ssrf_f) = ssrf_hit {
                        if fired_chains.insert(format!("{}::{}", ssrf_f.core.id, PLUGIN_CLOUD_METADATA)) {
                            if let Some(cloud_meta) = plugins.iter().find(|p| p.name() == PLUGIN_CLOUD_METADATA) {
                                if !self.layer_policy.needs_approval(cloud_meta.metadata().layer) || approval_gate.is_approved(cloud_meta.name()).await {
                                    info!("🔱 V15 SOVEREIGN: SSRF detected! Triggering reactive Cloud Metadata extraction for {}", target.host);
                                    
                                    // Extract URL from evidence
                                    let tool_name = ssrf_f.evidence.evidence.as_ref()
                                        .and_then(|e| e.data.get("tool"))
                                        .and_then(|t| t.as_str());

                                    let vuln_url = if tool_name == Some("ssrfmap") {
                                         ssrf_f.evidence.evidence.as_ref()
                                            .and_then(|e| e.data.get("url"))
                                            .and_then(|u| u.as_str())
                                            .map(|s| s.to_string())
                                    } else {
                                        // Fallback for ssrf_king or others: use target.host
                                        Some(target.host.clone())
                                    };

                                    if let Some(url) = vuln_url {
                                        let mut reactive_snapshot = target.clone();
                                        Arc::make_mut(&mut reactive_snapshot.extra_data)
                                            .as_object_mut()
                                            .and_then(|obj| obj.insert("ssrf_url".into(), serde_json::json!(url)));

                                        if let Ok(mut cloud_findings) = cloud_meta.scan(&reactive_snapshot).await {
                                            extra_findings.append(&mut cloud_findings);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    // --- END REACTIVE TRIGGER: SSRF ---

                    all_findings.append(&mut extra_findings);

                    // --- Automated Finding Enrichment ---
                    for f in all_findings.iter_mut() {
                        f.enrich_with_cvss();
                        if f.enrichment.ai_analysis.is_none() {
                             if let Some(poc) = crate::utils::poc_generator::PocGenerator::generate_suggested_poc(f) {
                                 f.enrichment.ai_analysis = Some(crate::models::AIAnalysis {
                                     summary: "Automated Mimikri enrichment".into(),
                                     impact: "Potential impact detected by scanner.".into(),
                                     stealth_notes: "Follow stealth policy for exploitation.".into(),
                                     risk_score: match f.core.severity {
                                         Severity::Critical => 90,
                                         Severity::High => 70,
                                         Severity::Medium => 50,
                                         _ => 20,
                                     },
                                     confidence: 0.7,
                                     mitre_attack: None,
                                     exploit_path: poc,
                                     model: "Mimikri-Engine".into(),
                                     poc: None,
                                     usage: Default::default(),
                                 });
                             }
                        }
                    }

                    for f in all_findings.iter_mut() {
                        f.core.version = target.version + 1;
                    }

                    // --- TRIAGE ENGINE DEDUPLICATION ---
                    all_findings = crate::plugins::triage::process(all_findings).await;

                    Arc::make_mut(&mut target.findings).append(&mut all_findings);
                    target.version += 1;
                }
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
                    Arc::make_mut(&mut target.tool_suggestions).extend(suggestions);
                }

                if plugin_error {
                    target.status = TargetStatus::Error;
                    target.version += 1;
                }

                if target.status == TargetStatus::Scanning {
                     target.status = TargetStatus::Scanned;
                     target.version += 1;
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

        while let Some(mut result) = processed_stream.next().await {
            result.scan_id = self.current_scan_id;
            if let Some(ref pool) = self.db_pool {
                if let Err(e) = crate::core::temporal::diff_target(pool, &mut result).await {
                    error!("Temporal diff failed for {}: {}", result.host, e);
                }
            }
            if let Err(e) = output_tx.send(result).await {
                error!("Failed to send result to output channel: {}", e);
                break; // Downstream closed
            }
        }
        
        info!("Orchestrator finished processing.");
            }
        }
    }
}
