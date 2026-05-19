use crate::models::{TargetHost, ScanMetadata};
use super::DataSink;
use anyhow::Result;
use std::sync::Arc;
use async_trait::async_trait;

/// A DataSink that writes findings to the activity log (timeline.jsonl).
pub struct TimelineSink {
    logger: Arc<crate::utils::activity_log::ActivityLog>,
}

impl TimelineSink {
    pub fn new(logger: Arc<crate::utils::activity_log::ActivityLog>) -> Self {
        Self { logger }
    }
}

#[async_trait]
impl DataSink for TimelineSink {
    async fn write(&mut self, target: &TargetHost) -> Result<()> {
        for finding in target.findings.iter() {
            let _ = self.logger.log_finding(finding, crate::utils::activity_log::Actor::Sentinel, Some(&target.host)).await;
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
