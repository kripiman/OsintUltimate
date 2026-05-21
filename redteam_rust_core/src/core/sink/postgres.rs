use crate::models::{TargetHost, ScanMetadata};
use super::DataSink;
use anyhow::{Context, Result};
use sqlx::PgPool;
use async_trait::async_trait;
use std::path::PathBuf;

/// A DataSink that writes results to a SQLite database.
pub struct PostgresSink {
    pub(crate) pool: PgPool,
    scan_id: Option<i64>,
    command_line: String,
}

impl PostgresSink {
    pub async fn new(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let path_str = path.to_string_lossy();
        
        let connection_str = if path_str.starts_with("postgres://") || path_str.starts_with("postgresql://") {
            path_str.into_owned()
        } else {
            std::env::var("DATABASE_URL")
                .map_err(|_| anyhow::anyhow!("DATABASE_URL environment variable is missing and path is not a postgres URL"))?
        };
        
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(50)
            .connect(&connection_str)
            .await?;

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

    /// V14.7: Expose pool reference for BountySink dedup queries.
    pub fn pool(&self) -> &sqlx::PgPool {
        &self.pool
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
            let scrubbed_desc = crate::core::ai::scrubber::SCRUBBER.scrub(&finding.core.description);
            let evidence = crate::core::ai::scrubber::SCRUBBER.scrub(&serde_json::to_string(&finding.evidence)?);
            let enrichment = crate::core::ai::scrubber::SCRUBBER.scrub(&serde_json::to_string(&finding.enrichment)?);
            let context = crate::core::ai::scrubber::SCRUBBER.scrub(&serde_json::to_string(&finding.context)?);
            
            sqlx::query(
                "INSERT INTO findings (id, target_id, category, severity, description, evidence, enrichment, context, timestamps)
                 VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7::jsonb, $8::jsonb, $9) ON CONFLICT(id) DO UPDATE SET category = EXCLUDED.category, severity = EXCLUDED.severity, description = EXCLUDED.description, evidence = EXCLUDED.evidence, enrichment = EXCLUDED.enrichment - 'is_new', context = EXCLUDED.context, timestamps = EXCLUDED.timestamps"
            )
            .bind(&finding.core.id)
            .bind(target_id)
            .bind(format!("{:?}", finding.core.category))
            .bind(format!("{:?}", finding.core.severity))
            .bind(scrubbed_desc)
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

    fn get_db_pool(&self) -> Option<sqlx::PgPool> {
        Some(self.pool.clone())
    }

    fn get_scan_id(&self) -> Option<i64> {
        self.scan_id
    }
}
