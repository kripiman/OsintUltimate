use crate::models::{TargetHost, ScanMetadata, Finding};
use crate::core::sink::DataSink;
use anyhow::Result;
use async_trait::async_trait;
use std::sync::{Arc, Mutex};

/// A simple in-memory sink that buffers all findings for verification/baselining.
#[derive(Clone, Default)]
pub struct BufferedSink {
    findings: Arc<Mutex<Vec<Finding>>>,
}

impl BufferedSink {
    pub fn new() -> Self {
        Self {
            findings: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub async fn get_findings(&self) -> Vec<Finding> {
        self.findings.lock().unwrap().clone()
    }
}

#[async_trait]
impl DataSink for BufferedSink {
    async fn write(&mut self, target: &TargetHost) -> Result<()> {
        let mut lock = self.findings.lock().unwrap();
        println!("📥 BufferedSink: Received {} findings from {}", target.findings.len(), target.host);
        for mut finding in target.findings.iter().cloned() {
            finding.core.target = Some(target.host.clone());
            lock.push(finding);
        }
        Ok(())
    }

    async fn write_metadata(&mut self, _metadata: &ScanMetadata) -> Result<()> {
        Ok(())
    }

    async fn close(&mut self) -> Result<()> {
        Ok(())
    }
}
