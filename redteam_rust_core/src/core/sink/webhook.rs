use crate::models::{TargetHost, ScanMetadata};
use super::DataSink;
use anyhow::{Context, Result};
use flate2::write::GzEncoder;
use flate2::Compression;
use std::sync::Arc;
use std::io::Write;
use async_trait::async_trait;

/// V10 HARDENING: Tactical Webhook Sink for C2/Exfiltration.
/// Uses reqwest to send results to a remote endpoint in real-time.
pub struct TacticalWebhookSink {
    proxy_manager: Arc<crate::utils::proxy::ProxyManager>,
    url: String,
    auth_token: String,
    buffer: Vec<TargetHost>,
    batch_size: usize,
}

impl TacticalWebhookSink {
    pub fn new(url: String, auth_token: Option<String>, pm: Arc<crate::utils::proxy::ProxyManager>) -> Result<Self> {
        let token = auth_token.context("Security Violation: C2 Webhook integration requires C2_TOKEN for authorization. Cannot send findings without authentication.")?;
        Ok(Self {
            proxy_manager: pm,
            url,
            auth_token: token,
            buffer: Vec::with_capacity(10),
            batch_size: 10,
        })
    }

    async fn flush(&mut self) -> Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }

        let json = serde_json::to_string(&self.buffer)
            .context("TacticalWebhookSink: Failed to serialize batch to JSON")?;
        
        let scrubbed_json = crate::core::ai::scrubber::SCRUBBER.scrub(&json);
        
        // Gzip compression for remote latency optimization
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(scrubbed_json.as_bytes())?;
        let compressed_data = encoder.finish()?;

        let host = url::Url::parse(&self.url)?.host_str().unwrap_or("c2-server").to_string();
        let (_, client) = self.proxy_manager.get_client_fail_closed(&host)?;

        let mut request = client.post(&self.url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::CONTENT_ENCODING, "gzip")
            .body(compressed_data);
        
        request = request.header("Authorization", format!("Bearer {}", self.auth_token));

        request.send().await.context("TacticalWebhookSink: Failed to send batched result to C2")?;
        
        self.buffer.clear();
        Ok(())
    }
}

#[async_trait]
impl DataSink for TacticalWebhookSink {
    async fn write(&mut self, target: &TargetHost) -> Result<()> {
        self.buffer.push(target.clone());
        if self.buffer.len() >= self.batch_size {
            self.flush().await?;
        }
        Ok(())
    }

    async fn write_metadata(&mut self, metadata: &ScanMetadata) -> Result<()> {
        let host = url::Url::parse(&self.url)?.host_str().unwrap_or("c2-server").to_string();
        let (_, client) = self.proxy_manager.get_client_fail_closed(&host)?;

        let mut request = client.post(format!("{}/metadata", self.url))
            .json(metadata);
            
        request = request.header("Authorization", format!("Bearer {}", self.auth_token));

        request.send().await.context("TacticalWebhookSink: Failed to send metadata to C2")?;
        Ok(())
    }

    async fn close(&mut self) -> Result<()> {
        self.flush().await?;
        Ok(())
    }
}
