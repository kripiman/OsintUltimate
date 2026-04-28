use std::path::PathBuf;
use serde::{Serialize, Deserialize};
use anyhow::{Result, Context};
use tokio::fs::{File, OpenOptions};
use tokio::io::AsyncWriteExt;
use std::sync::Arc;
use tokio::sync::Mutex;
use crate::models::Finding;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    ToolCall,
    Finding,
    AgentStep,
    Note,
    Objective,
    System,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Actor {
    Scout,
    Exploiter,
    C2,
    Reporter,
    System,
    Sentinel, // For the main autonomous agent
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEvent {
    pub ts: f64,
    pub kind: EventKind,
    pub actor: Actor,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default)]
    pub data: serde_json::Value,
}

pub struct ActivityLog {
    path: PathBuf,
    file: Arc<Mutex<File>>,
}

impl ActivityLog {
    pub async fn new(path: PathBuf) -> Result<Self> {
        // Ensure parent directories exist
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await
            .with_context(|| format!("ActivityLog: Failed to open log file at {}", path.display()))?;

        Ok(Self {
            path,
            file: Arc::new(Mutex::new(file)),
        })
    }

    pub async fn log(&self, kind: EventKind, actor: Actor, message: &str, target: Option<&str>, data: serde_json::Value) -> Result<()> {
        let event = LogEvent {
            ts: chrono::Utc::now().timestamp_millis() as f64 / 1000.0,
            kind,
            actor,
            message: message.to_string(),
            target: target.map(|s| s.to_string()),
            data,
        };

        let mut line = serde_json::to_string(&event)?;
        line.push('\n');

        let mut file = self.file.lock().await;
        file.write_all(line.as_bytes()).await?;
        file.flush().await?;

        Ok(())
    }

    pub async fn log_finding(&self, finding: &Finding, actor: Actor, target: Option<&str>) -> Result<()> {
        self.log(
            EventKind::Finding,
            actor,
            &format!("New finding discovered: {}", finding.core.title),
            target,
            serde_json::to_value(finding)?,
        ).await
    }

    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_activity_log_creation_and_append() -> Result<()> {
        let dir = tempdir()?;
        let log_path = dir.path().join("timeline.jsonl");
        let logger = ActivityLog::new(log_path.clone()).await?;

        logger.log(EventKind::Note, Actor::System, "Test event", None, serde_json::json!({"test": true})).await?;

        let content = tokio::fs::read_to_string(log_path).await?;
        let event: LogEvent = serde_json::from_str(&content)?;

        assert_eq!(event.message, "Test event");
        assert_eq!(event.kind, EventKind::Note);
        assert!(event.data["test"].as_bool().unwrap());

        Ok(())
    }
}
