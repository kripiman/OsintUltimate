use crate::models::{TargetHost, ScanMetadata};
use anyhow::{Context, Result};
use async_trait::async_trait;
use tokio::io::AsyncWriteExt;
use std::path::PathBuf;
use sqlx::PgPool;
use flate2::write::GzEncoder;
use flate2::Compression;
use std::sync::Arc;
use std::io::Write;
use tracing::{info, error};
use crate::models::{Finding, Severity, ReportPlatform};
use crate::plugins::reporting::platform_client::PlatformClient;
use crate::utils::bounty_exporter::BountyExporter;
pub mod nats_sink;

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
}

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

        let json = serde_json::to_vec(&self.buffer)
            .context("TacticalWebhookSink: Failed to serialize batch to JSON")?;
        
        // Gzip compression for remote latency optimization
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&json)?;
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

/// A DataSink that writes results to a SQLite database.
pub struct PostgresSink {
    pub(crate) pool: PgPool,
    scan_id: Option<i64>,
    command_line: String,
}

impl PostgresSink {
    pub async fn new(path: impl Into<PathBuf>) -> Result<Self> {
        let _path = path.into();
        let connection_str = std::env::var("DATABASE_URL").unwrap_or_else(|_| "postgres://osintuser:WENYANULTRA_SECURE_PASS@localhost:5432/osintdb".to_string());
        
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(50)
            .connect(&connection_str)
            .await?;

        // Initialize schema
        

        

        

        

        

        

        

        

        

        

        // V14.2: Initialize the DeduplicationEngine with the persistent pool
        crate::utils::deduplication::DeduplicationEngine::init(pool.clone()).await?;

        // V14.2: Initialize CveCacheManager (Phase B)
        crate::utils::cve_cache::CveCacheManager::init(pool.clone());

        Ok(Self {
            pool,
            scan_id: None,
            command_line: String::new(),
        })
    }

    /// V15: Saves a plugin execution result to the persistent cache.
    pub async fn save_plugin_cache(&self, cache_key: &str, output: &str) -> Result<()> {
        sqlx::query(
            "INSERT INTO plugin_cache (cache_key, output, timestamp) VALUES ($1, $2, CURRENT_TIMESTAMP) ON CONFLICT(cache_key) DO UPDATE SET output = EXCLUDED.output, timestamp = EXCLUDED.timestamp"
        )
        .bind(cache_key)
        .bind(output)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// V15: Loads a plugin execution result from the persistent cache.
    pub async fn load_plugin_cache(&self, cache_key: &str) -> Result<Option<String>> {
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT output FROM plugin_cache WHERE cache_key = $1"
        )
        .bind(cache_key)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| r.0))
    }

    /// PHASE 5: Recuperar todas las estadísticas de MCP
    pub async fn get_mcp_stats(&self) -> Result<std::collections::HashMap<String, i64>> {
        let rows: Vec<(String, i64)> = sqlx::query_as(
            "SELECT stat_key, stat_value FROM mcp_stats"
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().collect())
    }

    /// PHASE 5: Actualizar/Incrementar estadísticas de forma atómica
    pub async fn update_mcp_stats(&self, stats: std::collections::HashMap<String, i64>) -> Result<()> {
        for (key, value) in stats {
            sqlx::query(
                "INSERT INTO mcp_stats (stat_key, stat_value) VALUES ($1, $2)
                 ON CONFLICT(stat_key) DO UPDATE SET stat_value = mcp_stats.stat_value + EXCLUDED.stat_value"
            )
            .bind(key)
            .bind(value)
            .execute(&self.pool)
            .await?;
        }
        Ok(())
    }

    /// V15: Persistencia de checkpoints para continuidad (MCP-OSINTULT port)
    pub async fn save_checkpoint(&self, trigger: &str, manifest: &str, content: &str) -> Result<()> {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        let digest: String = hex::encode(hasher.finalize());

        sqlx::query(
            "INSERT INTO checkpoints (trigger, digest, manifest, content, timestamp)
             VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP) ON CONFLICT(trigger, digest) DO UPDATE SET manifest = EXCLUDED.manifest, content = EXCLUDED.content, timestamp = EXCLUDED.timestamp"
        )
        .bind(trigger)
        .bind(digest)
        .bind(manifest)
        .bind(content)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn load_checkpoint(&self, trigger: &str, digest: &str) -> Result<Option<String>> {
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT content FROM checkpoints WHERE trigger = $1 AND digest = $2"
        )
        .bind(trigger)
        .bind(digest)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| r.0))
    }

    /// V15: Persists an agent session state to allow mission resumption.
    pub async fn save_agent_session(&self, session: &AgentSession) -> Result<()> {
        sqlx::query(
            "INSERT INTO agent_sessions (id, agent_role, target_id, posture, memory_json, last_updated)
             VALUES ($1, $2, $3, $4, $5::jsonb, CURRENT_TIMESTAMP) ON CONFLICT(id) DO UPDATE SET posture = EXCLUDED.posture, memory_json = EXCLUDED.memory_json, last_updated = EXCLUDED.last_updated"
        )
        .bind(&session.id)
        .bind(&session.agent_role)
        .bind(session.target_id)
        .bind(&session.posture)
        .bind(&session.memory_json)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// V15: Loads an agent session state for a specific target.
    pub async fn load_agent_session(&self, session_id: &str) -> Result<Option<AgentSession>> {
        let res: Option<AgentSession> = sqlx::query_as(
            "SELECT id, agent_role, target_id, posture, memory_json::text FROM agent_sessions WHERE id = $1"
        )
        .bind(session_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(res)
    }

    /// PHASE 2: Saves or updates an operational objective.
    pub async fn save_objective(&self, objective: &crate::models::Objective) -> Result<()> {
        sqlx::query(
            "INSERT INTO objectives (id, title, description, status, depends_on, priority, agent_assigned, updated_at)
             VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, CURRENT_TIMESTAMP) ON CONFLICT(id) DO UPDATE SET status = EXCLUDED.status, depends_on = EXCLUDED.depends_on, priority = EXCLUDED.priority, agent_assigned = EXCLUDED.agent_assigned, updated_at = EXCLUDED.updated_at"
        )
        .bind(&objective.id)
        .bind(&objective.title)
        .bind(&objective.description)
        .bind(format!("{:?}", objective.status))
        .bind(serde_json::to_string(&objective.depends_on).unwrap_or_default())
        .bind(objective.priority as i64)
        .bind(&objective.agent_assigned)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

/// V15 Persistent Agent Mission State
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, sqlx::FromRow)]
pub struct AgentSession {
    pub id: String,          // Unique session/project ID
    pub agent_role: String,   // ghost / strike / breach
    pub target_id: i64,      // FK to targets table
    pub posture: String,     // Active OPSEC level
    pub memory_json: String,  // Serialized AdaptiveContext/Findings
}

#[async_trait]
impl DataSink for PostgresSink {
    async fn write(&mut self, target: &TargetHost) -> Result<()> {
        let scan_id = self.scan_id.context("PostgresSink: scan_id not initialized (write_metadata must be called first)")?;
        
        // Insert or update target
        let row: (i32,) = sqlx::query_as(
            "INSERT INTO targets (scan_id, host, ip, status) VALUES ($1, $2, $3, $4) RETURNING id"
        )
        .bind(scan_id)
        .bind(&target.host)
        .bind(&target.ip)
        .bind(format!("{:?}", target.status))
        .fetch_one(&self.pool)
        .await?;
        
        let target_id = row.0 as i32;

        // Insert findings
        for finding in target.findings.iter() {
            let evidence = serde_json::to_string(&finding.evidence)?;
            let enrichment = serde_json::to_string(&finding.enrichment)?;
            let context = serde_json::to_string(&finding.context)?;
            
            sqlx::query(
                "INSERT INTO findings (id, target_id, category, severity, description, evidence, enrichment, context, timestamps)
                 VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7::jsonb, $8::jsonb, $9) ON CONFLICT(id) DO UPDATE SET category = EXCLUDED.category, severity = EXCLUDED.severity, description = EXCLUDED.description, evidence = EXCLUDED.evidence, enrichment = EXCLUDED.enrichment, context = EXCLUDED.context, timestamps = EXCLUDED.timestamps"
            )
            .bind(&finding.core.id)
            .bind(target_id)
            .bind(format!("{:?}", finding.core.category))
            .bind(format!("{:?}", finding.core.severity))
            .bind(&finding.core.description)
            .bind(evidence)
            .bind(enrichment)
            .bind(context)
            .bind(finding.core.timestamps)
            .execute(&self.pool)
            .await?;
        }

        Ok(())
    }

    async fn write_metadata(&mut self, metadata: &ScanMetadata) -> Result<()> {
        self.command_line = metadata.command_line.clone();
        
        let row: (i32,) = sqlx::query_as(
            "INSERT INTO scans (command_line) VALUES ($1) RETURNING id"
        )
        .bind(&metadata.command_line)
        .fetch_one(&self.pool)
        .await?;
        
        self.scan_id = Some(row.0 as i64);
        Ok(())
    }

    async fn close(&mut self) -> Result<()> {
        self.pool.close().await;
        Ok(())
    }
}

/// A DataSink that generates a professional Markdown report.
pub struct MarkdownSink {
    file: tokio::fs::File,
    findings_count: usize,
}

impl MarkdownSink {
    pub async fn new(path: impl Into<PathBuf>) -> Result<Self> {
        let file = tokio::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path.into())
            .await?;
        Ok(Self { file, findings_count: 0 })
    }
}

#[async_trait]
impl DataSink for MarkdownSink {
    async fn write(&mut self, target: &TargetHost) -> Result<()> {
        let mut report = format!("\n## Target: {} (IP: {})\n", target.host, target.ip.as_deref().unwrap_or("Unknown"));
        report.push_str("| ID | Severity | Category | Description |\n");
        report.push_str("|----|----------|----------|-------------|\n");
        
        for f in target.findings.iter() {
            self.findings_count += 1;
            report.push_str(&format!("| {} | **{:?}** | {:?} | {} |\n", f.core.id, f.core.severity, f.core.category, f.core.description));
            
            if let Some(ai) = &f.enrichment.ai_analysis {
                report.push_str(&format!("\n> ### AI Analysis (Model: {})\n", ai.model));
                report.push_str(&format!("> **Summary:** {}\n", ai.summary));
                report.push_str(&format!("> **Impact:** {}\n", ai.impact));
                report.push_str(&format!("> **Exploit Path:** {}\n", ai.exploit_path));
                if let Some(mitre) = &ai.mitre_attack {
                    let mitre_tags: Vec<String> = mitre.iter().map(|s| s.to_string()).collect();
                    report.push_str(&format!("> **MITRE ATT&CK:** {}\n", mitre_tags.join(", ")));
                }
            }
        }
        
        self.file.write_all(report.as_bytes()).await?;
        Ok(())
    }

    async fn write_metadata(&mut self, metadata: &ScanMetadata) -> Result<()> {
        let header = format!("# OSINT ULTIMATE - Professional Pentest Report\n\n- **Date:** {}\n- **Command:** `{}`\n\n---\n", 
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
            metadata.command_line);
        self.file.write_all(header.as_bytes()).await?;
        Ok(())
    }

    async fn close(&mut self) -> Result<()> {
        let footer = format!("\n---\n**Total Findings:** {}\n*Generated by OsintUltimate Sentinel Agent*", self.findings_count);
        self.file.write_all(footer.as_bytes()).await?;
        self.file.flush().await?;
        Ok(())
    }
}

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
    async fn write(&mut self, target: &crate::models::TargetHost) -> Result<()> {
        for finding in target.findings.iter() {
            let _ = self.logger.log_finding(finding, crate::utils::activity_log::Actor::Sentinel, Some(&target.host)).await;
        }
        Ok(())
    }

    async fn write_metadata(&mut self, _metadata: &crate::models::ScanMetadata) -> Result<()> {
        Ok(())
    }

    async fn close(&mut self) -> Result<()> {
        Ok(())
    }
}

/// V14.2: Bug Bounty Automated Submission Sink.
/// Buffers High/Critical findings and submits them to H1/Bugcrowd/Intigriti upon scan completion.
pub struct BountySink {
    findings: Vec<Finding>,
    h1_username: Option<String>,
    h1_api_key: Option<String>,
    bugcrowd_api_key: Option<String>,
    intigriti_token: Option<String>,
    program_handle: Option<String>,
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
        }
    }

    async fn submit_to_platform(&self, platform: ReportPlatform, api_key: &str, username: Option<String>) -> Result<()> {
        let handle = self.program_handle.as_deref().unwrap_or("default");
        let client = PlatformClient::new(platform.clone(), api_key.to_string(), username);
        
        let eligible_refs: Vec<&Finding> = self.findings.iter().collect();
        if eligible_refs.is_empty() { return Ok(()); }

        let report_md = BountyExporter::generate(&eligible_refs, &platform);
        let title = format!("Automated Findings Report - {} items", eligible_refs.len());
        
        // Use highest severity found
        let max_severity = self.findings.iter()
            .map(|f| f.core.severity.clone())
            .max_by_key(|s| match s {
                Severity::Critical => 4,
                Severity::High => 3,
                Severity::Medium => 2,
                Severity::Low => 1,
                Severity::Info => 0,
            })
            .unwrap_or(Severity::High);

        match client.submit(&report_md, &title, &max_severity, handle).await {
            Ok(url) => info!("🚀 [BountySink] Successfully submitted to {}: {}", platform.display_name(), url),
            Err(e) => error!("❌ [BountySink] Failed to submit to {}: {}", platform.display_name(), e),
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

        info!("🛡️ [BountySink] Finalizing scan. Attempting automated submissions for {} High/Critical findings...", self.findings.len());

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
