use std::sync::Arc;
use tokio::sync::mpsc;
use anyhow::Result;
use crate::models::{TargetHost, ScanMetadata};
use crate::core::sink::DataSink;
use crate::core::lock_free_sink::LockFreeResultSink;
use crate::core::filter::FalsePositiveFilter;
use crate::core::pipeline::enrichment::enrich_target_findings_static;

pub async fn run_sink_stage(
    sink: Box<dyn DataSink>,
    mut rx: mpsc::Receiver<TargetHost>,
    fp_filter: Arc<FalsePositiveFilter>,
) -> Result<()> {
    let v4_sink = Arc::new(LockFreeResultSink::new());
    v4_sink.start_worker(sink);

    while let Some(mut target) = rx.recv().await {
        enrich_target_findings_static(&mut target).await;
        Arc::make_mut(&mut target.findings).retain(|f| fp_filter.evaluate(f));
        v4_sink.enqueue(target);
    }
    
    v4_sink.stop();
    Ok(())
}

pub async fn start_sink_stage(
    mut sink: Box<dyn DataSink>,
    cmd_line: &str,
    fp_filter: Arc<FalsePositiveFilter>,
) -> Result<(mpsc::Sender<TargetHost>, tokio::task::JoinHandle<()>)> {
    sink.write_metadata(&ScanMetadata::new(cmd_line)).await?;
    
    let (tx, mut rx) = mpsc::channel::<TargetHost>(100);
    
    let handle = tokio::spawn(async move {
        while let Some(mut target) = rx.recv().await {
            enrich_target_findings_static(&mut target).await;
            Arc::make_mut(&mut target.findings).retain(|f| fp_filter.evaluate(f));
            let _ = sink.write(&target).await;
        }
        let _ = sink.close().await;
    });

    Ok((tx, handle))
}
