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
        let mut processed_stream = stream.map(|mut target| {
            let plugins = plugins.clone();
            async move {
                target.status = TargetStatus::Scanning;
                
                // QA-005 FIX: Use Arc only for read-only sharing. Collect findings via JoinSet return values.
                let target_ref = Arc::new(target);
                
                // CRIT-003 & HIGH-009 FIX: Parallel execution + Panic Isolation via tokio::spawn
                let mut join_set = tokio::task::JoinSet::new();
                for i in 0..plugins.len() {
                    let plugins_clone = plugins.clone();
                    let target_clone = target_ref.clone();
                    join_set.spawn(async move {
                        let p = &plugins_clone[i];
                        (p.name(), p.scan(&target_clone).await)
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
