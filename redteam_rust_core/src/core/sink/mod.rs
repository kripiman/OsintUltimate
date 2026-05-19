use crate::models::{TargetHost, ScanMetadata};
use anyhow::Result;
use async_trait::async_trait;

pub mod nats_sink;
pub mod buffered;
pub mod jsonl;
pub mod postgres;
pub mod webhook;
pub mod markdown;
pub mod timeline;
pub mod bounty;
pub mod bounty_draft;

pub use buffered::BufferedSink;
pub use jsonl::JsonlSink;
pub use postgres::{PostgresSink, AgentSession};
pub use webhook::TacticalWebhookSink;
pub use markdown::MarkdownSink;
pub use timeline::TimelineSink;
pub use bounty::BountySink;
pub use bounty_draft::BugBountyDraftSink;

/// Trait for defining where scan results should be written.
#[async_trait]
pub trait DataSink: Send + Sync {
    /// Write a single completed TargetHost to the sink.
    async fn write(&mut self, target: &TargetHost) -> Result<()>;
    
    /// Write scan metadata to the sink.
    async fn write_metadata(&mut self, metadata: &ScanMetadata) -> Result<()>;
    
    /// Finalize the sink (e.g., flush buffers, close files).
    async fn close(&mut self) -> Result<()>;
    
    /// Optional: Retrieve the underlying DB pool if applicable
    fn get_db_pool(&self) -> Option<sqlx::PgPool> { None }
    
    /// Optional: Retrieve the scan_id if initialized by the sink
    fn get_scan_id(&self) -> Option<i64> { None }
}

/// A DataSink that broadcasts to multiple other sinks.
pub struct MultiSink {
    sinks: Vec<Box<dyn DataSink>>,
}

impl Default for MultiSink {
    fn default() -> Self {
        Self::new()
    }
}

impl MultiSink {
    pub fn new() -> Self {
        Self { sinks: Vec::new() }
    }

    pub fn add(&mut self, sink: Box<dyn DataSink>) {
        self.sinks.push(sink);
    }
}

#[async_trait]
impl DataSink for MultiSink {
    async fn write(&mut self, target: &TargetHost) -> Result<()> {
        for sink in &mut self.sinks {
            sink.write(target).await?;
        }
        Ok(())
    }

    async fn write_metadata(&mut self, metadata: &ScanMetadata) -> Result<()> {
        for sink in &mut self.sinks {
            sink.write_metadata(metadata).await?;
        }
        Ok(())
    }

    async fn close(&mut self) -> Result<()> {
        for sink in &mut self.sinks {
            sink.close().await?;
        }
        Ok(())
    }

    fn get_db_pool(&self) -> Option<sqlx::PgPool> {
        self.sinks.iter().find_map(|s| s.get_db_pool())
    }

    fn get_scan_id(&self) -> Option<i64> {
        self.sinks.iter().find_map(|s| s.get_scan_id())
    }
}
