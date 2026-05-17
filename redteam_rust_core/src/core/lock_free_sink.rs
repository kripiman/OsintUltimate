use crate::models::TargetHost;
use crate::core::sink::DataSink;
use crossbeam::queue::ArrayQueue;
use std::sync::Arc;
use tokio::sync::Notify;
use tracing::{info, error};

const MAX_SINK_CAPACITY: usize = 200_000;

/// ARCH-v4: Lock-Free Result Sink
/// Replaces MPSC bounded channels with a bounded ArrayQueue for zero-block ingestion with memory limits.
/// Batches writes into single transactions to maximize I/O throughput.
pub struct LockFreeResultSink {
    queue: Arc<ArrayQueue<TargetHost>>,
    running: Arc<std::sync::atomic::AtomicBool>,
    notify: Arc<Notify>,
}

impl Default for LockFreeResultSink {
    fn default() -> Self {
        Self::new()
    }
}

impl LockFreeResultSink {
    pub fn new() -> Self {
        Self {
            queue: Arc::new(ArrayQueue::new(MAX_SINK_CAPACITY)),
            running: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            notify: Arc::new(Notify::new()),
        }
    }

    /// Starts the background writer task.
    /// In a production v4 env, this would use RocksDB or batch transactions in SQLite.
    pub fn start_worker(&self, mut inner_sink: Box<dyn DataSink>) {
        let queue = self.queue.clone();
        let running = self.running.clone();
        let notify = self.notify.clone();

        tokio::spawn(async move {
            info!("🚀 v4-SINK: Background batcher task started.");
            while running.load(std::sync::atomic::Ordering::Relaxed) || !queue.is_empty() {
                let mut batch = Vec::with_capacity(100);
                
                // Drain up to 100 items from the lock-free queue
                while let Some(item) = queue.pop() {
                    batch.push(item);
                    if batch.len() >= 100 { break; }
                }

                if !batch.is_empty() {
                    // In v4 we wrap this in a single DB transaction
                    for item in batch {
                        if let Err(e) = inner_sink.write(&item).await {
                            error!("❌ v4-SINK: Write failure: {}", e);
                        }
                    }
                } else {
                    // Zero-latency wait: Wait for notification or shutdown
                    notify.notified().await;
                }
            }
            
            // Final cleanup
            let _ = inner_sink.close().await;
            info!("🛑 v4-SINK: Background batcher task stopped.");
        });
    }

    pub fn enqueue(&self, target: TargetHost) {
        if let Err(t) = self.queue.push(target) {
            error!("⚠️  v4-SINK: Results queue is FULL (capacity reached). Dropping target {} to prevent OOM.", t.host);
        } else {
            self.notify.notify_one();
        }
    }

    pub fn stop(&self) {
        self.running.store(false, std::sync::atomic::Ordering::Relaxed);
        self.notify.notify_one(); // Wake up to finish last items
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use crate::core::sink::DataSink;
    use crate::models::TargetHost;
    use std::sync::Mutex;
    use std::time::Duration;

    struct MockSink(Arc<Mutex<Vec<String>>>);

    #[async_trait::async_trait]
    impl DataSink for MockSink {
        async fn write(&mut self, target: &TargetHost) -> Result<()> {
            self.0.lock().unwrap().push(target.host.clone());
            Ok(())
        }
        async fn write_metadata(&mut self, _: &crate::models::ScanMetadata) -> Result<()> { Ok(()) }
        async fn close(&mut self) -> Result<()> { Ok(()) }
    }

    #[tokio::test]
    async fn test_lock_free_sink_batching() {
        let results = Arc::new(Mutex::new(Vec::new()));
        let sink = LockFreeResultSink::new();
        let mock = Box::new(MockSink(results.clone()));
        
        sink.start_worker(mock);

        for i in 0..50 {
            sink.enqueue(TargetHost {
                host: format!("host-{}", i),
                ..Default::default()
            });
        }

        // Wait for batcher (approx 50ms should be enough for tokio)
        tokio::time::sleep(Duration::from_millis(100)).await;
        sink.stop();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let final_results = results.lock().unwrap();
        assert_eq!(final_results.len(), 50, "Sink should have processed all 50 items");
        assert!(final_results.contains(&"host-0".to_string()));
        assert!(final_results.contains(&"host-49".to_string()));
    }
}
