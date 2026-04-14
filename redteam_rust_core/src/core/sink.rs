use crate::models::{TargetHost, ScanMetadata};
use anyhow::{Context, Result};
use async_trait::async_trait;
use tokio::io::AsyncWriteExt;
use std::path::PathBuf;
use sqlx::{SqlitePool, sqlite::SqliteConnectOptions, Row};
use std::str::FromStr;
use flate2::write::GzEncoder;
use flate2::Compression;
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
    client: reqwest::Client,
    url: String,
    auth_token: String,
    buffer: Vec<TargetHost>,
    batch_size: usize,
}

impl TacticalWebhookSink {
    pub fn new(url: String, auth_token: Option<String>) -> Result<Self> {
        let token = auth_token.context("Security Violation: C2 Webhook integration requires C2_TOKEN for authorization. Cannot send findings without authentication.")?;
        Ok(Self {
            client: reqwest::Client::builder().danger_accept_invalid_certs(false).build()?,
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

        let mut request = self.client.post(&self.url)
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
        let mut request = self.client.post(&format!("{}/metadata", self.url))
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
    pool: SqlitePool,
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
                remediation TEXT,
                mitre_attack TEXT,
                ai_analysis TEXT,
                FOREIGN KEY(target_id) REFERENCES targets(id)
            )"
        ).execute(&pool).await?;

        Ok(Self {
            pool,
            scan_id: None,
            command_line: String::new(),
        })
    }
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
                "INSERT OR REPLACE INTO findings (id, target_id, category, severity, description, evidence, remediation, mitre_attack, ai_analysis)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
            )
            .bind(&finding.id)
            .bind(target_id)
            .bind(format!("{:?}", finding.category))
            .bind(format!("{:?}", finding.severity))
            .bind(&finding.description)
            .bind(evidence)
            .bind(&finding.remediation)
            .bind(mitre)
            .bind(ai)
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
                report.push_str(&format!("> **Remediation:** {}\n", ai.remediation));
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
