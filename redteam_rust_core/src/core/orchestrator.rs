use crate::models::{TargetHost, Finding, Severity, Category, TargetStatus, FINDING_PLUGIN_ERROR, FINDING_PLUGIN_PANIC};
use crate::plugins::ScannerPlugin;
use std::sync::Arc;
use futures::stream::StreamExt;
use tracing::{info, error};

pub struct Orchestrator {
    plugins: Vec<Box<dyn ScannerPlugin>>,
    concurrency: usize,
}

impl Orchestrator {
    pub fn new(concurrency: usize) -> Self {
        Self {
            plugins: Vec::new(),
            concurrency,
        }
    }

    pub fn register_plugin(&mut self, plugin: Box<dyn ScannerPlugin>) {
        self.plugins.push(plugin);
    }

    // V5 FIX: Allow channel to drain rather than aborting abruptly on trace
    // The previous implementation dropped mid-air targets by returning None immediately.
    // Now, we will always listen on rx.recv() until it naturally returns None (meaning previous stage dropped sender).
    pub async fn run(
        self, // Consumes self to fix plugins list (CRIT-004)
        input_rx: tokio::sync::mpsc::Receiver<TargetHost>,
        output_tx: tokio::sync::mpsc::Sender<TargetHost>,
        shutdown_token: tokio_util::sync::CancellationToken, 
    ) {
        info!("Orchestrator started. Concurrency: {}", self.concurrency);
        let plugins = Arc::new(self.plugins); // Share among concurrent target tasks

        let output_tx_clone = output_tx.clone();
        let stream = futures::stream::unfold((input_rx, shutdown_token.clone(), output_tx_clone), |(mut rx, token, out_tx)| async move {
            tokio::select! {
                val = rx.recv() => val.map(|t| (t, (rx, token, out_tx))),
                _ = token.cancelled() => {
                    // V10 FIX (HIGH-001): Drain rx explicitly to avoid discarding targets upon cancellation.
                    rx.close();
                    while let Ok(mut remaining_target) = rx.try_recv() {
                        remaining_target.status = TargetStatus::Dead;
                        remaining_target.findings.push(Finding::new(
                            "SHUTDOWN_ABORT",
                            Category::Availability,
                            Severity::Info,
                            "Target scan aborted due to graceful shutdown",
                            serde_json::json!({"host": remaining_target.host})
                        ));
                        let _ = out_tx.send(remaining_target).await;
                    }
                    None // Graceful shutdown
                }
            }
        });

        tokio::pin!(stream);

        // Process concurrently up to `concurrency` limit
        let mut processed_stream = stream.map(|mut target| {
            let plugins = plugins.clone();
            async move {
                target.status = TargetStatus::Scanning;
                
                // AUDIT-003 FIX: Use Arc to share TargetHost across plugin tasks instead of cloning for each.
                let mut target_arc = Arc::new(target);
                
                // CRIT-003 & HIGH-009 FIX: Parallel execution + Panic Isolation via tokio::spawn
                let futures = (0..plugins.len()).map(|i| {
                    let plugins_clone = plugins.clone();
                    let target_clone = target_arc.clone();
                    tokio::task::spawn(async move {
                        let p = &plugins_clone[i];
                        (p.name(), p.scan(&target_clone).await)
                    })
                });

                let results = futures::future::join_all(futures).await;

                for join_res in results {
                    match join_res {
                        Ok((name, res)) => {
                            // Note: Since target_arc is shared among all futures, 
                            // we need to collect findings and merge them back later
                            // OR we need to rethink this if TargetHost is mutated.
                            // Currently, ScannerPlugin::scan takes &TargetHost, so it shouldn't mutate it.
                            // Wait, the orchestrator appends findings to 'target'.
                            // If we use Arc, we need to handle the mutation.
                            // The easiest way is to collect findings from results.
                            match res {
                                Ok(mut findings) => {
                                    // findings are already extracted from plugin.scan
                                    // We will merge them into the final target below.
                                    let mut target = Arc::make_mut(&mut target_arc);
                                    target.findings.append(&mut findings);
                                }
                                Err(e) => {
                                    error!("Plugin {} error on {}: {}", name, target_arc.host, e);
                                    let mut target = Arc::make_mut(&mut target_arc);
                                    target.findings.push(Finding::new(
                                        FINDING_PLUGIN_ERROR,
                                        Category::Misconfiguration,
                                        Severity::Info, 
                                        &format!("Plugin {} failed", name),
                                        serde_json::json!({"error": e.to_string()})
                                    ));
                                    target.status = TargetStatus::Error;
                                }
                            }
                        }
                        Err(join_err) => {
                            // This captures panics in tokio::spawned tasks
                            error!("Target task panicked: {}", join_err);
                            let mut target = Arc::make_mut(&mut target_arc);
                            target.findings.push(Finding::new(
                                FINDING_PLUGIN_PANIC,
                                Category::Misconfiguration,
                                Severity::Critical, 
                                "A scanner plugin panicked during execution!",
                                serde_json::json!({"error": join_err.to_string()})
                            ));
                            target.status = TargetStatus::Error;
                        }
                    }
                }
                
                // Extract the final target from Arc. Since we are the only owner now (all clones dropped),
                // we can unwrap or make_mut.
                let mut target = Arc::try_unwrap(target_arc).unwrap_or_else(|a| (*a).clone());

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
