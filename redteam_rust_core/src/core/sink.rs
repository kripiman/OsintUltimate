use crate::models::{TargetHost, ScanMetadata};
use anyhow::{Context, Result};
use async_trait::async_trait;
use tokio::io::AsyncWriteExt;
use std::path::PathBuf;

/// Trait for defining where scan results should be written.
#[async_trait]
pub trait DataSink: Send + Sync {
    /// Write a single completed TargetHost to the sink.
    async fn write(&mut self, target: &TargetHost) -> Result<()>;
    
    /// Write scan metadata to the sink.
    async fn write_metadata(&mut self, metadata: &ScanMetadata) -> Result<()>;
    
    /// Finalize the sink (e.g., flush buffers, close files).
    async fn close(&mut self) -> Result<()>;
}

/// A DataSink that writes results as JSON Lines to a file.
/// This guarantees O(1) memory usage by flushing results as they arrive.
pub struct JsonlSink {
    file: tokio::fs::File,
    path: PathBuf,
}

impl JsonlSink {
    /// Creates a new JsonlSink, truncating any existing file at the path.
    pub async fn new(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let file = tokio::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true) // AUDIT-002 FIX: Truncate by default to avoid pollution and metadata issues
            .open(&path)
            .await
            .context("JsonlSink: Failed to open output file")?;
            
        Ok(Self { file, path })
    }
    
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
}

#[async_trait]
impl DataSink for JsonlSink {
    async fn write(&mut self, target: &TargetHost) -> Result<()> {
        let mut json = serde_json::to_string(target)
            .context("JsonlSink: Failed to serialize TargetHost to JSON")?;
            
        // Ensure NewLine is appended for JSONL format
        json.push('\n');
        
        // Write out the serialized byte buffer
        self.file.write_all(json.as_bytes())
            .await
            .context("JsonlSink: Failed to write bytes to JSONL file")?;
            
        // QA-011: Trade-off — flush per-write ensures crash-durability but reduces throughput.
        // For high-throughput scans, consider a batched-flush strategy (e.g., flush every N writes
        // or time-based via a background task). Current default prioritizes data safety.
        self.file.flush().await.context("JsonlSink: Failed to flush to disk")?;
            
        Ok(())
    }

    async fn write_metadata(&mut self, metadata: &ScanMetadata) -> Result<()> {
        let mut json = serde_json::to_string(metadata)
            .context("JsonlSink: Failed to serialize ScanMetadata to JSON")?;
        json.push('\n');
        self.file.write_all(json.as_bytes()).await?;
        self.file.flush().await?;
        Ok(())
    }
    
    async fn close(&mut self) -> Result<()> {
        self.file.flush().await.context("JsonlSink: Failed to flush file content to disk")?;
        Ok(())
    }
}
