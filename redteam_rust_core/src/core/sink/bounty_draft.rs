use crate::models::{TargetHost, ScanMetadata};
use super::DataSink;
use anyhow::Result;
use std::path::PathBuf;
use async_trait::async_trait;
use tracing::{info, error};

/// Phase 1: Bug Bounty Draft Sink.
/// Automatically generates professional Markdown reports for all Medium+ findings
/// and saves them to the workspace/reports/drafts/ directory.
pub struct BugBountyDraftSink {
    reports_dir: PathBuf,
}

impl BugBountyDraftSink {
    /// Creates a new BugBountyDraftSink.
    pub async fn new(workspace_path: PathBuf) -> Self {
        let reports_dir = workspace_path.join("reports").join("drafts");
        
        if let Err(e) = tokio::fs::create_dir_all(&reports_dir).await {
            error!("⚠️ [BugBountyDraftSink] Failed to create reports directory {}: {}. Sink will be inactive.", reports_dir.display(), e);
        } else {
            info!("📁 [BugBountyDraftSink] Reports will be saved to: {}", reports_dir.display());
        }
        
        Self { reports_dir }
    }
}

#[async_trait]
impl DataSink for BugBountyDraftSink {
    async fn write(&mut self, target: &TargetHost) -> Result<()> {
        let reports = crate::plugins::reporting::bug_bounty::generate_reports(target);
        
        for report in reports {
            let file_path = self.reports_dir.join(&report.filename);
            
            // Overwrite policy: Overwrite existing drafts to ensure they reflect the latest data.
            match tokio::fs::write(&file_path, report.content).await {
                Ok(_) => info!("📝 [BugBountyDraftSink] Generated draft: {}", report.filename),
                Err(e) => error!("❌ [BugBountyDraftSink] Failed to write report {}: {}", report.filename, e),
            }
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
