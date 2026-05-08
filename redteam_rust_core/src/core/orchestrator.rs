use crate::models::{TargetHost, Finding, Severity, Category, TargetStatus, FINDING_PLUGIN_ERROR, FINDING_PLUGIN_PANIC, FINDING_SSTI, FINDING_SBOM_INVENTORY, FINDING_GRAPHQL_INTROSPECTION, FINDING_KATANA_ENDPOINT, FINDING_WAYMORE_URL, FINDING_JS_ENDPOINT, FINDING_TECH_STACK};
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
                for i in 0..plugins.len() {
                    let p = &plugins[i];
                    
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
                
                info!("🔱 ORCHESTRATOR: Swarm processing finished for {}. Findings: {}", target_ref.host, all_findings.len());

                // QA-005 FIX: Remove from dashboard_targets temporarily to drop the Arc reference count.
                // This allows Arc::try_unwrap to succeed and gives us unique ownership without deep cloning.
                dashboard_targets.remove(&target_ref.host);

                let mut target = Arc::try_unwrap(target_ref)
                    .unwrap_or_else(|arc| (*arc).clone());
                
                if !all_findings.is_empty() {
                    let fired_chains: DashSet<String> = DashSet::new();
                    let mut extra_findings = Vec::new();
                    // --- REACTIVE TRIGGER: SSTI -> COMMIX ---
                    let ssti_hit = all_findings.iter().find(|f| f.core.id == FINDING_SSTI).cloned();
                    if let Some(ssti_f) = ssti_hit {
                        if fired_chains.insert(format!("{}::{}", ssti_f.core.id, PLUGIN_COMMIX)) {
                            if let Some(commix) = plugins.iter().find(|p| p.name() == PLUGIN_COMMIX) {
                                if !self.layer_policy.needs_approval(commix.metadata().layer) || approval_gate.is_approved(commix.name()).await {
                                    info!("🔱 V14.3 SOVEREIGN: SSTI detected! Triggering reactive Commix chain for {}", target.host);
                                    
                                    // Pass vulnerable URL into snapshot extra_data
                                    let vuln_url = ssti_f.evidence.evidence.as_ref()
                                        .and_then(|e| e.data.get("url"))
                                        .cloned();
                                    
                                    let mut reactive_snapshot = TargetHost {
                                        host: target.host.clone(),
                                        ip: target.ip.clone(),
                                        resolved_ip: target.resolved_ip.clone(),
                                        target_type: target.target_type,
                file_path: None,
                                        user: None,
                                        status: TargetStatus::Scanning,
                                        findings: Arc::new(Vec::new()),
                                        tool_suggestions: Arc::new(Vec::new()),
                                        tactical_context: Arc::clone(&target.tactical_context),
                                        extra_data: Arc::clone(&target.extra_data),
                                        version: target.version,
                                        skip_heavy_scan: target.skip_heavy_scan,
                                    };

                                    if let Some(url) = vuln_url {
                                        Arc::make_mut(&mut reactive_snapshot.extra_data)
                                            .as_object_mut()
                                            .and_then(|obj| obj.insert("discovered_urls".into(), serde_json::json!([url])));
                                    }

                                    if let Ok(mut rce_findings) = commix.scan(&reactive_snapshot).await {
                                        if !rce_findings.is_empty() {
                                            info!("🔥 V14.3 SOVEREIGN: Commix confirmed RCE from SSTI on {}", target.host);
                                            extra_findings.append(&mut rce_findings);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    // --- END REACTIVE TRIGGER: SSTI ---
                    
                    // --- REACTIVE TRIGGER: SBOM -> GRYPE/COSIGN ---
                    let sbom_hit = all_findings.iter().find(|f| f.core.id == FINDING_SBOM_INVENTORY).cloned();
                    if let Some(sbom_f) = sbom_hit {
                        for chain_plugin_name in &[PLUGIN_GRYPE, PLUGIN_COSIGN] {
                            if fired_chains.insert(format!("{}::{}", sbom_f.core.id, chain_plugin_name)) {
                                if let Some(plugin) = plugins.iter().find(|p| p.name() == *chain_plugin_name) {
                                    if !self.layer_policy.needs_approval(plugin.metadata().layer) || approval_gate.is_approved(plugin.name()).await {
                                        info!("🔱 V14.3 SOVEREIGN: SBOM detected! Triggering reactive {} for {}", plugin.name(), target.host);
                                        if let Ok(mut chain_findings) = plugin.scan(&target).await {
                                            extra_findings.append(&mut chain_findings);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    // --- END REACTIVE TRIGGER: SBOM ---

                    // --- REACTIVE TRIGGER: GRAPHQL -> API FUZZ ---
                    let gql_hit = all_findings.iter()
                        .find(|f| f.core.id == FINDING_GRAPHQL_INTROSPECTION).cloned();
                    
                    if let Some(f) = gql_hit {
                        if let Some(url) = f.evidence.evidence.as_ref()
                            .and_then(|e| e.data.get("url"))
                            .and_then(|u| u.as_str())
                        {
                            let url = url.to_string();
                        tracing::trace!("🔍 REACTIVE_DEBUG: Found GRAPHQL-INTROSPECTION. URL: {}", url);

                        for chain_plugin_name in &[PLUGIN_GRAPHW00F, PLUGIN_SCHEMATHESIS, PLUGIN_CRACKQL] {
                            if fired_chains.insert(format!("{}::{}", f.core.id, chain_plugin_name)) {
                                if let Some(plugin) = plugins.iter().find(|p| p.name() == *chain_plugin_name) {
                                    let needs_appr = self.layer_policy.needs_approval(plugin.metadata().layer);
                                    let is_appr = approval_gate.is_approved(plugin.name()).await;
                                    
                                    tracing::trace!("🔍 REACTIVE_DEBUG: Tool {} | Needs Approval: {} | Is Approved: {}", plugin.name(), needs_appr, is_appr);

                                    if !needs_appr || is_appr {
                                        info!("🔱 V14.3 SOVEREIGN: GraphQL Introspection detected! Triggering reactive {} for {}", plugin.name(), target.host);
                                        
                                        let mut reactive_snapshot = target.clone();
                                        Arc::make_mut(&mut reactive_snapshot.extra_data)
                                            .as_object_mut()
                                            .and_then(|obj| {
                                                obj.insert("api_schema_url".into(), url.clone().into());
                                                obj.insert("discovered_urls".into(), serde_json::json!([url]));
                                                Some(obj)
                                            });

                                        if let Ok(mut api_findings) = plugin.scan(&reactive_snapshot).await {
                                            extra_findings.append(&mut api_findings);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                    // --- END REACTIVE TRIGGER: GRAPHQL ---

                    // --- REACTIVE TRIGGER: JS DISCOVERY ---
                    let js_hit = all_findings.iter().find(|f| f.core.id == "JS-FILES-DISCOVERED").cloned();
                    if let Some(f) = js_hit {
                        for chain_plugin_name in &["retire", "sourcemapper"] {
                            if fired_chains.insert(format!("{}::{}", f.core.id, chain_plugin_name)) {
                                if let Some(plugin) = plugins.iter().find(|p| p.name() == *chain_plugin_name) {
                                    if !self.layer_policy.needs_approval(plugin.metadata().layer) || approval_gate.is_approved(plugin.name()).await {
                                        info!("🔱 V14.3 SOVEREIGN: JS files discovered! Triggering reactive {} for {}", plugin.name(), target.host);
                                        if let Ok(mut findings) = plugin.scan(&target).await {
                                            extra_findings.append(&mut findings);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    // --- END REACTIVE TRIGGER: JS DISCOVERY ---
                    
                    // --- REACTIVE TRIGGER: HIDDEN PARAMS -> SQLMAP ---
                    let arjun_hit = all_findings.iter().find(|f| f.core.id == FINDING_HIDDEN_PARAMS).cloned();
                    if let Some(f) = arjun_hit {
                        if fired_chains.insert(format!("{}::{}", f.core.id, PLUGIN_SQLMAP)) {
                            if let Some(sqlmap) = plugins.iter().find(|p| p.name() == PLUGIN_SQLMAP) {
                                if !self.layer_policy.needs_approval(sqlmap.metadata().layer) || approval_gate.is_approved(sqlmap.name()).await {
                                    info!("🔱 V14.8 SOVEREIGN: Hidden parameters discovered! Triggering reactive SqlMap for {}", target.host);
                                    
                                    let mut reactive_snapshot = target.clone();
                                    if let Some(params) = f.evidence.evidence.as_ref()
                                        .and_then(|e| e.data.get("parameters"))
                                        .and_then(|p| p.as_array()) {
                                            let param_list: Vec<String> = params.iter().filter_map(|p| p.as_str().map(|s| s.to_string())).collect();
                                            Arc::make_mut(&mut reactive_snapshot.extra_data)
                                                .as_object_mut()
                                                .and_then(|obj| obj.insert("injected_parameters".into(), serde_json::json!(param_list)));
                                    }

                                    if let Ok(mut sql_findings) = sqlmap.scan(&reactive_snapshot).await {
                                        extra_findings.append(&mut sql_findings);
                                    }
                                }
                            }
                        }
                    }

                    // --- REACTIVE TRIGGER: MOBILE ARTIFACTS (V14.8) ---
                    #[cfg(feature = "sovereign")]
                    {
                        let apk_regex = regex::Regex::new(r"\.apk($|\?)").unwrap();
                        let mobile_hit = all_findings.iter().find(|finding| {
                            if finding.core.id == FINDING_KATANA_ENDPOINT || finding.core.id == FINDING_WAYMORE_URL || finding.core.id == FINDING_JS_ENDPOINT {
                                if let Some(evidence) = finding.evidence.evidence.as_ref() {
                                    let content = evidence.data.to_string();
                                    return apk_regex.is_match(&content);
                                }
                            }
                            false
                        }).cloned();

                        if let Some(f) = mobile_hit {
                            let mut mobile_findings = Vec::new();
                            for chain_plugin_name in &[PLUGIN_MOBSF, PLUGIN_APKLEAKS, PLUGIN_APKTOOL, PLUGIN_JADX, PLUGIN_DROZER, PLUGIN_FRIDA, PLUGIN_OBJECTION, PLUGIN_MARIANA_TRENCH] {
                                if fired_chains.insert(format!("{}::{}", f.core.id, chain_plugin_name)) {
                                    if let Some(plugin) = plugins.iter().find(|p| p.name() == *chain_plugin_name) {
                                        if !self.layer_policy.needs_approval(plugin.metadata().layer) || approval_gate.is_approved(plugin.name()).await {
                                            info!("🔱 V14.8 SOVEREIGN: Mobile artifact detected! Triggering reactive {} for {}", plugin.name(), target.host);
                                            if let Ok(mut findings) = plugin.scan(&target).await {
                                                mobile_findings.append(&mut findings);
                                            }
                                        }
                                    }
                                }
                            }
                            extra_findings.append(&mut mobile_findings);
                        }
                    }

                    // --- REACTIVE TRIGGER: CLOUD INFRASTRUCTURE (V14.8) ---
                    #[cfg(feature = "sovereign")]
                    {
                        let cloud_keywords = ["kubernetes", "k8s", "s3-bucket", "aws-metadata", "gcp-identity", "azure-storage", "lambda", "fargate"];
                        let cloud_hit = all_findings.iter().find(|f| {
                            if f.core.id == FINDING_TECH_STACK || f.core.id == "NSE-SCRIPT" {
                                if let Some(evidence) = f.evidence.evidence.as_ref() {
                                    let content = evidence.data.to_string().to_lowercase();
                                    return cloud_keywords.iter().any(|&k| content.contains(k));
                                }
                            }
                            false
                        }).cloned();

                        if let Some(f) = cloud_hit {
                            let mut cloud_findings = Vec::new();
                            for chain_plugin_name in &[PLUGIN_KUBE_BENCH, PLUGIN_KUBESCAPE, PLUGIN_PROWLER, PLUGIN_SCOUTSUITE] {
                                if fired_chains.insert(format!("{}::{}", f.core.id, chain_plugin_name)) {
                                    if let Some(plugin) = plugins.iter().find(|p| p.name() == *chain_plugin_name) {
                                        if !self.layer_policy.needs_approval(plugin.metadata().layer) || approval_gate.is_approved(plugin.name()).await {
                                            info!("🔱 V14.8 SOVEREIGN: Cloud infrastructure detected! Triggering reactive {} for {}", plugin.name(), target.host);
                                            if let Ok(mut findings) = plugin.scan(&target).await {
                                                cloud_findings.append(&mut findings);
                                            }
                                        }
                                    }
                                }
                            }
                            extra_findings.append(&mut cloud_findings);
                        }
                    }

                    // --- REACTIVE TRIGGER: AI/LLM SECURITY (V14.8) ---
                    #[cfg(feature = "sovereign")]
                    {
                        let ai_keywords = ["openai", "anthropic", "ollama", "vllm", "mistral", "llama", "langchain"];
                        let ai_hit = all_findings.iter().find(|f| {
                            if f.core.id == FINDING_TECH_STACK || f.core.id == FINDING_JS_ENDPOINT {
                                if let Some(evidence) = f.evidence.evidence.as_ref() {
                                    let content = evidence.data.to_string().to_lowercase();
                                    let has_keyword = ai_keywords.iter().any(|&k| content.contains(k));
                                    let has_endpoint = content.contains("/v1/chat/completions") || content.contains("api.openai.com") || content.contains(":11434");
                                    return has_keyword && has_endpoint;
                                }
                            }
                            false
                        }).cloned();

                        if let Some(f) = ai_hit {
                            let mut ai_findings = Vec::new();
                            for chain_plugin_name in &[PLUGIN_GARAK, PLUGIN_PROMPTMAP, PLUGIN_LLMFUZZER] {
                                if fired_chains.insert(format!("{}::{}", f.core.id, chain_plugin_name)) {
                                    if let Some(plugin) = plugins.iter().find(|p| p.name() == *chain_plugin_name) {
                                        if !self.layer_policy.needs_approval(plugin.metadata().layer) || approval_gate.is_approved(plugin.name()).await {
                                            info!("🔱 V14.8 SOVEREIGN: AI endpoint detected! Triggering reactive {} for {}", plugin.name(), target.host);
                                            if let Ok(mut findings) = plugin.scan(&target).await {
                                                ai_findings.append(&mut findings);
                                            }
                                        }
                                    }
                                }
                            }
                            extra_findings.append(&mut ai_findings);
                        }
                    }

                    // --- REACTIVE TRIGGER: SOURCE-CODE-EXPOSED -> SEMGREP ---
                    let source_hit = all_findings.iter().find(|f| f.core.id == FINDING_SOURCE_CODE_EXPOSED).cloned();
                    if let Some(f) = source_hit {
                        if fired_chains.insert(format!("{}::{}", f.core.id, PLUGIN_SEMGREP)) {
                            if let Some(plugin) = plugins.iter().find(|p| p.name() == PLUGIN_SEMGREP) {
                                if !self.layer_policy.needs_approval(plugin.metadata().layer) || approval_gate.is_approved(plugin.name()).await {
                                    info!("SOVEREIGN: Source code exposed! Triggering reactive Semgrep for {}", target.host);
                                    if let Ok(mut findings) = plugin.scan(&target).await {
                                        extra_findings.append(&mut findings);
                                    }
                                }
                            }
                        }
                    }

                    // --- REACTIVE TRIGGER: DESERIALIZATION -> GADGET DETECTOR ---
                    let deserialization_hit = all_findings.iter().find(|f| f.core.id == FINDING_JAVA_SERIAL || f.core.id == FINDING_OBJECT_INJECTION).cloned();
                    if let Some(f) = deserialization_hit {
                        if fired_chains.insert(format!("{}::{}", f.core.id, PLUGIN_DESERIALIZATION)) {
                            if let Some(plugin) = plugins.iter().find(|p| p.name() == PLUGIN_DESERIALIZATION) {
                                if !self.layer_policy.needs_approval(plugin.metadata().layer) || approval_gate.is_approved(plugin.name()).await {
                                    info!("SOVEREIGN: Deserialization vulnerability suspected! Triggering reactive DeserializationGadgetDetector for {}", target.host);
                                    if let Ok(mut findings) = plugin.scan(&target).await {
                                        extra_findings.append(&mut findings);
                                    }
                                }
                            }
                        }
                    }

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

        while let Some(result) = processed_stream.next().await {
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
