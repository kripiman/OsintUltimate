use crate::models::{TargetHost, ScanMetadata};
use anyhow::{Context, Result};
use async_trait::async_trait;
use tokio::io::AsyncWriteExt;
use std::path::PathBuf;
use sqlx::{SqlitePool, sqlite::SqliteConnectOptions};
use std::str::FromStr;
use flate2::write::GzEncoder;
use flate2::Compression;
use std::sync::Arc;
use std::io::Write;

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

        let mut request = client.post(&format!("{}/metadata", self.url))
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
pub struct SqliteSink {
    pub(crate) pool: SqlitePool,
    scan_id: Option<i64>,
    command_line: String,
}

impl SqliteSink {
    pub async fn new(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let connection_str = format!("sqlite://{}", path.display());
        
        let options = SqliteConnectOptions::from_str(&connection_str)?
            .create_if_missing(true)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal);

        let pool = SqlitePool::connect_with(options).await?;

        // Initialize schema
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                command_line TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )"
        ).execute(&pool).await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                host TEXT NOT NULL,
                ip TEXT,
                status TEXT NOT NULL,
                FOREIGN KEY(scan_id) REFERENCES scans(id)
            )"
        ).execute(&pool).await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                target_id INTEGER NOT NULL,
                category TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT NOT NULL,
                evidence TEXT NOT NULL,
                tactical_path TEXT,
                mitre_attack TEXT,
                ai_analysis TEXT,
                cvss_vector TEXT,
                objective_id TEXT,
                agent TEXT,
                iteration INTEGER,
                FOREIGN KEY(target_id) REFERENCES targets(id)
            )"
        ).execute(&pool).await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS objectives (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                status TEXT NOT NULL,
                depends_on TEXT,
                priority INTEGER NOT NULL,
                agent_assigned TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )"
        ).execute(&pool).await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS agent_sessions (
                id TEXT PRIMARY KEY,
                agent_role TEXT NOT NULL,
                target_id INTEGER NOT NULL,
                posture TEXT NOT NULL,
                memory_json TEXT NOT NULL,
                last_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(target_id) REFERENCES targets(id)
            )"
        ).execute(&pool).await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS plugin_cache (
                cache_key TEXT PRIMARY KEY,
                output TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )"
        ).execute(&pool).await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS mcp_stats (
                stat_key TEXT PRIMARY KEY,
                stat_value INTEGER DEFAULT 0
            )"
        ).execute(&pool).await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS checkpoints (
                trigger TEXT NOT NULL,
                digest TEXT NOT NULL,
                manifest TEXT NOT NULL,
                content TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY(trigger, digest)
            )"
        ).execute(&pool).await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS deduplication (
                finding_hash BLOB PRIMARY KEY,
                first_seen INTEGER NOT NULL
            )"
        ).execute(&pool).await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS cve_cache (
                cve_id TEXT PRIMARY KEY,
                json_data TEXT NOT NULL,
                last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
            )"
        ).execute(&pool).await?;

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
            "INSERT OR REPLACE INTO plugin_cache (cache_key, output, timestamp) VALUES (?, ?, CURRENT_TIMESTAMP)"
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
            "SELECT output FROM plugin_cache WHERE cache_key = ?"
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
                "INSERT INTO mcp_stats (stat_key, stat_value) VALUES (?, ?)
                 ON CONFLICT(stat_key) DO UPDATE SET stat_value = stat_value + excluded.stat_value"
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
            "INSERT OR REPLACE INTO checkpoints (trigger, digest, manifest, content, timestamp)
             VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)"
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
            "SELECT content FROM checkpoints WHERE trigger = ? AND digest = ?"
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
            "INSERT OR REPLACE INTO agent_sessions (id, agent_role, target_id, posture, memory_json, last_updated)
             VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)"
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
            "SELECT id, agent_role, target_id, posture, memory_json FROM agent_sessions WHERE id = ?"
        )
        .bind(session_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(res)
    }

    /// PHASE 2: Saves or updates an operational objective.
    pub async fn save_objective(&self, objective: &crate::models::Objective) -> Result<()> {
        sqlx::query(
            "INSERT OR REPLACE INTO objectives (id, title, description, status, depends_on, priority, agent_assigned, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)"
        )
        .bind(&objective.id)
        .bind(&objective.title)
        .bind(&objective.description)
        .bind(format!("{:?}", objective.status))
        .bind(&serde_json::to_string(&objective.depends_on).unwrap_or_default())
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
impl DataSink for SqliteSink {
    async fn write(&mut self, target: &TargetHost) -> Result<()> {
        let scan_id = self.scan_id.context("SqliteSink: scan_id not initialized (write_metadata must be called first)")?;
        
        // Insert or update target
        let row: (i64,) = sqlx::query_as(
            "INSERT INTO targets (scan_id, host, ip, status) VALUES (?, ?, ?, ?) RETURNING id"
        )
        .bind(scan_id)
        .bind(&target.host)
        .bind(&target.ip)
        .bind(format!("{:?}", target.status))
        .fetch_one(&self.pool)
        .await?;
        
        let target_id = row.0;

        // Insert findings
        for finding in target.findings.iter() {
            let evidence = serde_json::to_string(&finding.evidence.data)?;
            let mitre = finding.mitre_attack.as_ref().map(|m| serde_json::to_string(m).unwrap_or_default());
            let ai = finding.ai_analysis.as_ref().map(|a| serde_json::to_string(a).unwrap_or_default());
            
            sqlx::query(
                "INSERT OR REPLACE INTO findings (id, target_id, category, severity, description, evidence, tactical_path, mitre_attack, ai_analysis, cvss_vector, objective_id, agent, iteration)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
            )
            .bind(&finding.id)
            .bind(target_id)
            .bind(format!("{:?}", finding.category))
            .bind(format!("{:?}", finding.severity))
            .bind(&finding.description)
            .bind(evidence)
            .bind(&finding.tactical_path)
            .bind(mitre)
            .bind(ai)
            .bind(&finding.cvss_vector)
            .bind(&finding.objective_id)
            .bind(&finding.agent)
            .bind(finding.iteration as i64)
            .execute(&self.pool)
            .await?;
        }

        Ok(())
    }

    async fn write_metadata(&mut self, metadata: &ScanMetadata) -> Result<()> {
        self.command_line = metadata.command_line.clone();
        
        let row: (i64,) = sqlx::query_as(
            "INSERT INTO scans (command_line) VALUES (?) RETURNING id"
        )
        .bind(&metadata.command_line)
        .fetch_one(&self.pool)
        .await?;
        
        self.scan_id = Some(row.0);
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
            report.push_str(&format!("| {} | **{:?}** | {:?} | {} |\n", f.id, f.severity, f.category, f.description));
            
            if let Some(ai) = &f.ai_analysis {
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
