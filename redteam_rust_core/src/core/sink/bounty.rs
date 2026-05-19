use crate::models::{TargetHost, ScanMetadata, Finding, Severity, ReportPlatform};
use super::DataSink;
use super::postgres::PostgresSink;
use anyhow::Result;
use std::sync::Arc;
use async_trait::async_trait;
use tracing::{info, error};
use crate::plugins::reporting::platform_client::PlatformClient;
use crate::utils::bounty_exporter::BountyExporter;

/// V14.7: Bug Bounty Automated Submission Sink.
/// Buffers High/Critical findings and submits them per-finding to H1/Bugcrowd/Intigriti.
/// Deduplicates via PostgreSQL to prevent re-submission across scans (account ban risk).
/// Triage readiness gate (≥70/100) prevents low-quality reports from auto-submitting.
pub struct BountySink {
    findings: Vec<Finding>,
    h1_username: Option<String>,
    h1_api_key: Option<String>,
    bugcrowd_api_key: Option<String>,
    intigriti_token: Option<String>,
    program_handle: Option<String>,
    db: Option<Arc<PostgresSink>>,  // V14.7: for dedup queries; None = dedup disabled
}

impl BountySink {
    pub fn new(
        h1_username: Option<String>,
        h1_api_key: Option<String>,
        bugcrowd_api_key: Option<String>,
        intigriti_token: Option<String>,
        program_handle: Option<String>,
    ) -> Self {
        Self {
            findings: Vec::new(),
            h1_username,
            h1_api_key,
            bugcrowd_api_key,
            intigriti_token,
            program_handle,
            db: None,  // V14.7: set via with_db() when PostgresSink is available
        }
    }

    /// V14.7: Attach PostgresSink for submission deduplication.
    pub fn with_db(mut self, db: Arc<PostgresSink>) -> Self {
        self.db = Some(db);
        self
    }

    /// V14.7: SHA-256(finding.core.id || '|' || program_handle).
    /// Single source of truth for the dedup hash — avoids duplicate computation.
    fn submission_hash(finding: &Finding, handle: &str) -> String {
        use sha2::{Sha256, Digest};
        let mut h = Sha256::new();
        h.update(format!("{}|{}", finding.core.id, handle).as_bytes());
        hex::encode(h.finalize())
    }

    /// Check if this finding was already submitted to the given platform.
    async fn is_already_submitted(
        &self,
        finding: &Finding,
        platform: &str,
        pool: &sqlx::PgPool,
    ) -> bool {
        let handle = self.program_handle.as_deref().unwrap_or("default");
        let hash = Self::submission_hash(finding, handle);
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM submitted_reports WHERE finding_hash = $1 AND platform = $2"
        )
        .bind(&hash)
        .bind(platform)
        .fetch_one(pool)
        .await
        .unwrap_or(0) > 0
    }

    /// Record a successful submission to prevent future re-submission.
    async fn record_submission(
        &self,
        finding: &Finding,
        platform: &str,
        submission_url: &str,
        pool: &sqlx::PgPool,
    ) {
        let handle = self.program_handle.as_deref().unwrap_or("default");
        let hash = Self::submission_hash(finding, handle);
        let _ = sqlx::query(
            "INSERT INTO submitted_reports (finding_hash, program_handle, platform, submission_url)
             VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING"
        )
        .bind(&hash)
        .bind(handle)
        .bind(platform)
        .bind(submission_url)
        .execute(pool)
        .await;
    }

    /// V14.7: Per-finding submission with triage gate + dedup.
    async fn submit_to_platform(
        &self,
        platform: ReportPlatform,
        api_key: &str,
        username: Option<String>,
    ) -> Result<()> {
        use crate::plugins::reporting::bug_bounty::triage_readiness_score;

        let handle = self.program_handle.as_deref().unwrap_or("default");
        let client = PlatformClient::new(platform.clone(), api_key.to_string(), username);
        let pool: Option<&sqlx::PgPool> = self.db.as_ref().map(|db| db.pool());
        let platform_str = platform.display_name().to_lowercase();

        for finding in &self.findings {
            // Gate 1: triage readiness score
            let score = triage_readiness_score(finding);
            if score < 70 {
                info!("[BountySink] Skipping '{}' — Triage score {}/100 < 70 threshold",
                    finding.core.id, score);
                continue;
            }

            // Gate 2: dedup (only when DB is available)
            if let Some(pool) = pool {
                if self.is_already_submitted(finding, &platform_str, pool).await {
                    info!("[BountySink] [DEDUP] '{}' already submitted to {} — skipping",
                        finding.core.id, platform.display_name());
                    continue;
                }
            }

            // Build and submit single-finding report
            let report_md = BountyExporter::generate(&[finding], &platform);
            let title = finding.core.title.clone();

            match client.submit(&report_md, &title, &finding.core.severity, handle).await {
                Ok(url) => {
                    info!("🚀 [BountySink] ✅ Submitted '{}' to {}: {}",
                        finding.core.id, platform.display_name(), url);
                    if let Some(pool) = pool {
                        self.record_submission(finding, &platform_str, &url, pool).await;
                    }
                }
                Err(e) => error!("❌ [BountySink] Failed '{}' on {}: {}",
                    finding.core.id, platform.display_name(), e),
            }
        }
        Ok(())
    }
}

#[async_trait]
impl DataSink for BountySink {
    async fn write(&mut self, target: &TargetHost) -> Result<()> {
        for finding in target.findings.iter() {
            if matches!(finding.core.severity, Severity::High | Severity::Critical) {
                self.findings.push(finding.clone());
            }
        }
        Ok(())
    }

    async fn write_metadata(&mut self, _metadata: &ScanMetadata) -> Result<()> {
        Ok(())
    }

    async fn close(&mut self) -> Result<()> {
        if self.findings.is_empty() {
            return Ok(());
        }

        info!("🛡️ [BountySink] Finalizing scan. Processing {} High/Critical findings (triage + dedup gates active)...",
            self.findings.len());

        if let Some(ref key) = self.h1_api_key {
            self.submit_to_platform(ReportPlatform::HackerOne, key, self.h1_username.clone()).await?;
        }

        if let Some(ref key) = self.bugcrowd_api_key {
            self.submit_to_platform(ReportPlatform::BugCrowd, key, None).await?;
        }

        if let Some(ref key) = self.intigriti_token {
            self.submit_to_platform(ReportPlatform::Intigriti, key, None).await?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Category, Severity};
    use serde_json::json;

    fn make_finding(id: &str) -> Finding {
        Finding::new(id, Category::Recon, Severity::High, "test finding", json!({}))
    }

    #[test]
    fn test_submission_hash_is_deterministic() {
        let f = make_finding("SQLI-001");
        let h1 = BountySink::submission_hash(&f, "hackerone/target-corp");
        let h2 = BountySink::submission_hash(&f, "hackerone/target-corp");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_submission_hash_is_hex_string() {
        let f = make_finding("XSS-042");
        let hash = BountySink::submission_hash(&f, "bugcrowd/acme");
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()), "hash must be hex: {hash}");
        assert_eq!(hash.len(), 64, "SHA-256 hex = 64 chars");
    }

    #[test]
    fn test_submission_hash_differs_by_program_handle() {
        let f = make_finding("RCE-007");
        let h_h1 = BountySink::submission_hash(&f, "hackerone/target");
        let h_bc = BountySink::submission_hash(&f, "bugcrowd/target");
        assert_ne!(h_h1, h_bc, "different programs must produce different hashes");
    }

    #[test]
    fn test_submission_hash_differs_by_finding_id() {
        let f1 = make_finding("SQLI-001");
        let f2 = make_finding("SQLI-002");
        let h1 = BountySink::submission_hash(&f1, "h1/prog");
        let h2 = BountySink::submission_hash(&f2, "h1/prog");
        assert_ne!(h1, h2, "different finding IDs must produce different hashes");
    }

    #[test]
    fn test_bounty_sink_new_has_no_db() {
        let sink = BountySink::new(None, None, None, None, Some("h1/prog".into()));
        assert!(sink.db.is_none(), "db must be None until with_db() is called");
    }
}
