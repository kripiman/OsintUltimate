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
    blackarch_bridge: Arc<crate::core::blackarch::BlackArchBridge>, // NUEVO
}

impl Orchestrator {
    pub fn new(
        plugins: Arc<Vec<Box<dyn ScannerPlugin>>>, 
        concurrency: usize,
        policy: ScanLayerPolicy,
        approval_gate: Arc<ApprovalGate>,
        blackarch_bridge: Arc<crate::core::blackarch::BlackArchBridge>,
    ) -> Self {
        Self {
            plugins,
            concurrency,
            policy,
            approval_gate,
            blackarch_bridge,
        }
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
                        remaining_target.findings.push(Finding::new(
                            "SHUTDOWN_ABORT",
                            Category::Availability,
                            Severity::Info,
                            "Target scan aborted due to graceful shutdown",
                            serde_json::json!({"host": remaining_target.host})
                        ));
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

        let mut processed_stream = stream.map(move |mut target| {
            let plugins = plugins.clone();
            let policy = policy;
            let approval_gate = approval_gate.clone();
            let blackarch_bridge = blackarch_bridge.clone();
            async move {
                target.status = TargetStatus::Scanning;
                
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

                    let plugins_clone = plugins.clone();
                    let target_clone = target_ref.clone();
                    let approval_gate = approval_gate.clone();

                    join_set.spawn(async move {
                        let p = &plugins_clone[i];
                        let meta = p.metadata();
                        
                        // ARCH-EXT: Context-aware filtering
                        if meta.target_type != target_clone.target_type {
                            return (p.name(), Ok(Vec::new()));
                        }

                        // NEW: ScanLayer Policy Enforcement
                        if !policy.is_plugin_allowed(meta.layer) {
                            return (p.name(), Ok(Vec::new()));
                        }

                        // NEW: Approval Gate Enforcement
                        if policy.needs_approval(meta.layer) {
                            // En una implementación real, esto podría ser interactivo.
                            // Aquí simulamos la verificación de aprobación previa.
                            if !approval_gate.is_approved(p.name()).await {
                                warn!("Skipping {} - Requires approval and none found.", p.name());
                                return (p.name(), Ok(Vec::new()));
                            }
                        }
                        
                        // ARCH-EXT: Auto-dependency check
                        match p.check_dependencies().await {
                            Ok(true) => (p.name(), p.scan(&target_clone).await),
                            Ok(false) => (p.name(), Ok(Vec::new())), // Skip if deps missing
                            Err(e) => (p.name(), Err(e)),
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
                
                // QA-005 FIX: All tasks are done, so we are the only Arc holder.
                // Extract owned target and append findings directly — no clone needed.
                let mut target = Arc::try_unwrap(target_ref)
                    .expect("QA-005: All JoinSet tasks completed, Arc must have refcount 1");
                target.findings.append(&mut all_findings);
                // --- NEW: BlackArch Dynamic Tool Suggestion ---
                let mut suggestions = Vec::new();
                for finding in &target.findings {
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
                    target.tool_suggestions.extend(suggestions);
                }

                if plugin_error {
                    target.status = TargetStatus::Error;
                }

                if target.status == TargetStatus::Scanning {
                     target.status = TargetStatus::Scanned;
                }
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
