use crate::models::{TargetHost, ScanMetadata};
use super::DataSink;
use anyhow::{Context, Result};
use tokio::io::AsyncWriteExt;
use std::path::PathBuf;
use async_trait::async_trait;

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
        let json = serde_json::to_string(target)
            .context("JsonlSink: Failed to serialize TargetHost to JSON")?;
            
        let mut scrubbed_json = crate::core::ai::scrubber::SCRUBBER.scrub(&json);
        // Ensure NewLine is appended for JSONL format
        scrubbed_json.push('\n');
        
        // Write out the serialized byte buffer
        self.file.write_all(scrubbed_json.as_bytes())
            .await
            .context("JsonlSink: Failed to write bytes to JSONL file")?;
            
        // QA-011: Trade-off — flush per-write ensures crash-durability but reduces throughput.
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
