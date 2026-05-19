use crate::models::{TargetHost, ScanMetadata};
use super::DataSink;
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::info;

/// SOVEREIGN: Decentralized DataSink using NATS JetStream for high-availability findings.
pub struct NatsSink {
    client: async_nats::Client,
    subject_prefix: String,
}

impl NatsSink {
    /// Connects to NATS and returns a new NatsSink.
    pub async fn new(url: &str, subject_prefix: &str) -> Result<Self> {
        info!("🔱 SOVEREIGN: Connecting to NATS Mesh at {}...", url);
        let client = async_nats::connect(url).await
            .context("Failed to connect to NATS for decentralized sink")?;
        
        Ok(Self {
            client,
            subject_prefix: subject_prefix.to_string(),
        })
    }
}

#[async_trait]
impl DataSink for NatsSink {
    async fn write(&mut self, target: &TargetHost) -> Result<()> {
        let payload = serde_json::to_vec(target)
            .context("Failed to serialize TargetHost for NATS")?;
        
        let subject = format!("{}.findings.{}", self.subject_prefix, target.host);
        self.client.publish(subject, payload.into()).await
            .context("Failed to publish finding to NATS")?;
            
        Ok(())
    }

    async fn write_metadata(&mut self, metadata: &ScanMetadata) -> Result<()> {
        let payload = serde_json::to_vec(metadata)
            .context("Failed to serialize ScanMetadata for NATS")?;
            
        let subject = format!("{}.control.metadata", self.subject_prefix);
        self.client.publish(subject, payload.into()).await
            .context("Failed to publish metadata to NATS")?;
            
        Ok(())
    }

    async fn close(&mut self) -> Result<()> {
        info!("🔱 SOVEREIGN: Closing NATS sink.");
        // async-nats client handles cleanup on drop, but we can flush if needed
        Ok(())
    }
}
