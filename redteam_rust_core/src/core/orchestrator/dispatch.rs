use std::sync::Arc;
use tokio::task::JoinSet;
use tracing::error;
use crate::models::{TargetHost, Finding, Category, Severity, TargetStatus, FINDING_PLUGIN_ERROR, FINDING_PLUGIN_PANIC};
use crate::plugins::ScannerPlugin;
use crate::core::capability_layer::ScanLayerPolicy;
use crate::core::approval_gate::ApprovalGate;
use super::{reactive, enrichment, scope_guard};

pub async fn dispatch_scan(
    target: Arc<TargetHost>,
    plugins: Arc<Vec<Box<dyn ScannerPlugin>>>,
    layer_policy: ScanLayerPolicy,
    approval_gate: Arc<ApprovalGate>,
    memory_semaphore: Arc<tokio::sync::Semaphore>,
    memory_monitor: Arc<crate::utils::memory_monitor::MemoryMonitor>,
    concurrency_semaphore: Arc<tokio::sync::Semaphore>,
    policy: Arc<dyn crate::core::policy::PolicyProvider>,
    strict_scope: bool,
    approval_timeout_secs: Option<u64>,
) -> (Vec<Finding>, bool) {
    let mut join_set = JoinSet::new();

    let priority_set: std::collections::HashSet<String> = target.tactical_context
        .get("priority_plugins")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect())
        .unwrap_or_default();

    for pass in [true, false] {
        for i in 0..plugins.len() {
            let p = &plugins[i];
            let is_priority = priority_set.contains(p.name());
            if pass != is_priority { continue; }
            
            if p.metadata().target_type != target.target_type {
                continue;
            }

            if p.metadata().is_monitor {
                continue;
            }

            let plugins_clone = Arc::clone(&plugins);
            let target_snapshot = TargetHost {
                host: target.host.clone(),
                ip: target.ip.clone(),
                resolved_ip: target.resolved_ip.clone(),
                target_type: target.target_type,
                file_path: target.file_path.clone(),
                user: target.user.clone(),
                status: target.status.clone(),
                findings: Arc::new(Vec::new()),
                tool_suggestions: Arc::new(Vec::new()),
                tactical_context: Arc::clone(&target.tactical_context),
                extra_data: Arc::clone(&target.extra_data),
                version: target.version,
                skip_heavy_scan: target.skip_heavy_scan,
                scan_id: target.scan_id,
                scope_id: target.scope_id.clone(),
            };
            
            let lp = layer_policy;
            let approval_gate = Arc::clone(&approval_gate);
            let memory_semaphore_clone = memory_semaphore.clone();
            let memory_monitor_clone = memory_monitor.clone();
            let concurrency_semaphore_clone = concurrency_semaphore.clone();
            let policy_clone = policy.clone();
            let strict_scope_val = strict_scope;

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
                
                let multiplier = if memory_monitor_clone.should_trigger_backpressure() {
                    2.0 
                } else {
                    1.0
                };
                
                let total_capacity = memory_monitor_clone.hard_limit_mb();
                let base_permits = meta.cost.max(1) * (total_capacity / 10).max(10);
                let permits_needed = ((base_permits as f32 * multiplier) as u32).min(total_capacity.saturating_sub(1));
                
                // Concurrency control: Acquire a spawner concurrency permit
                let _concurrency_permit = concurrency_semaphore_clone.acquire().await;
                let _permit = memory_semaphore_clone.acquire_many(permits_needed).await;
                
                match p.check_dependencies().await {
                    Ok(true) => (p.name().to_string(), p.execute_safe_scan(&target_snapshot, policy_clone, strict_scope_val, approval_gate, approval_timeout_secs).await),
                    Ok(false) => (p.name().to_string(), Ok(Vec::new())),
                    Err(e) => (p.name().to_string(), Err(e)),
                }
            });
        }
    }

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
                            f.core.scope_id = target.scope_id.clone();
                        }
                        all_findings.append(&mut findings);
                    }
                    Err(e) => {
                        error!("Plugin {} error on {}: {}", name, target.host, e);
                        all_findings.push(Finding::new(
                            FINDING_PLUGIN_ERROR,
                            Category::Misconfiguration,
                            Severity::Info, 
                            &format!("Plugin {} failed", name),
                            serde_json::json!({"error": e.to_string()})
                        ));
                        plugin_error = true;
                    }
                }
            }
            Err(join_err) => {
                error!("Target task panicked: {}", join_err);
                all_findings.push(Finding::new(
                    FINDING_PLUGIN_PANIC,
                    Category::Misconfiguration,
                    Severity::Critical, 
                    "A scanner plugin panicked during execution!",
                    serde_json::json!({"error": join_err.to_string()})
                ));
                plugin_error = true;
            }
        }
    }

    (all_findings, plugin_error)
}

pub struct TargetProcessContext {
    pub plugins: Arc<Vec<Box<dyn ScannerPlugin>>>,
    pub lp: ScanLayerPolicy,
    pub policy: Arc<dyn crate::core::policy::PolicyProvider>,
    pub strict_scope: bool,
    pub approval_gate: Arc<ApprovalGate>,
    pub blackarch_bridge: Arc<crate::core::blackarch::BlackArchBridge>,
    pub memory_semaphore: Arc<tokio::sync::Semaphore>,
    pub memory_monitor: Arc<crate::utils::memory_monitor::MemoryMonitor>,
    pub dashboard_tx: Option<tokio::sync::broadcast::Sender<Finding>>,
    pub dashboard_targets: Arc<dashmap::DashMap<String, TargetHost>>,
    pub inventory: Arc<crate::core::orchestrator::swarm::inventory::SwarmInventory>,
    pub approval_timeout_secs: Option<u64>,
    pub concurrency_semaphore: Arc<tokio::sync::Semaphore>,
}

pub async fn process_target(
    mut target: TargetHost,
    ctx: TargetProcessContext,
) -> TargetHost {
    // Scope check
    if !scope_guard::check_scope(&mut target, &ctx.policy, ctx.strict_scope) {
        return target;
    }

    // Memory backpressure
    if ctx.memory_monitor.is_critical() {
        while ctx.memory_monitor.is_critical() {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
    } else if ctx.memory_monitor.should_trigger_backpressure() {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }

    ctx.dashboard_targets.insert(target.host.clone(), target.clone());
    if let Some(ref tx) = ctx.dashboard_tx {
        for f in target.findings.iter() {
            let _ = tx.send(f.clone());
        }
    }

    target.status = TargetStatus::Scanning;
    target.version += 1;
    ctx.dashboard_targets.insert(target.host.clone(), target.clone());
    
    let target_arc = Arc::new(target);
    
    // Dispatch scan
    let (mut all_findings, plugin_error) = dispatch_scan(
        target_arc.clone(),
        ctx.plugins.clone(),
        ctx.lp,
        ctx.approval_gate.clone(),
        ctx.memory_semaphore,
        ctx.memory_monitor,
        ctx.concurrency_semaphore,
        ctx.policy.clone(),
        ctx.strict_scope,
        ctx.approval_timeout_secs,
    ).await;

    ctx.dashboard_targets.remove(&target_arc.host);
    let mut target = Arc::try_unwrap(target_arc).unwrap_or_else(|arc| (*arc).clone());

    if !all_findings.is_empty() {
        // Ingest findings
        for f in &all_findings {
            ctx.inventory.ingest_finding(f.clone(), crate::core::orchestrator::swarm::inventory::TrustLevel::Private);
        }

        // Reactive logic
        let mut extra = reactive::run_reactive_logic(
            &target, &all_findings, &ctx.plugins, &ctx.lp, &ctx.approval_gate, &ctx.inventory
        ).await;
        all_findings.append(&mut extra);

        // Enrichment
        enrichment::enrich_findings(&mut all_findings);

        for f in all_findings.iter_mut() {
            f.core.version = target.version + 1;
        }

        // Triage
        all_findings = crate::plugins::triage::process(all_findings).await;

        Arc::make_mut(&mut target.findings).append(&mut all_findings);
        target.version += 1;
    }

    // BlackArch suggestions
    let suggestions = enrichment::suggest_blackarch_tools(&target.findings, &ctx.blackarch_bridge);
    if !suggestions.is_empty() {
        Arc::make_mut(&mut target.tool_suggestions).extend(suggestions);
    }

    if plugin_error {
        target.status = TargetStatus::Error;
    } else if target.status == TargetStatus::Scanning {
        target.status = TargetStatus::Scanned;
    }
    target.version += 1;

    if let Some(ref tx) = ctx.dashboard_tx {
        for f in target.findings.iter() {
            let _ = tx.send(f.clone());
        }
    }
    ctx.dashboard_targets.insert(target.host.clone(), target.clone());

    target
}
