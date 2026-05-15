use serde::{Deserialize, Serialize};
use crate::models::Finding;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use anyhow::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpilledEvent {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub severity: String,
    pub finding_id: String,
    #[serde(flatten)]
    pub finding: Finding,
}

impl SpilledEvent {
    pub fn from_finding(finding: Finding) -> Self {
        Self {
            timestamp: chrono::Utc::now(),
            severity: format!("{:?}", finding.core.severity),
            finding_id: finding.core.id.clone(),
            finding,
        }
    }
}

pub struct NdjsonSpillWriter {
    path: String,
}

impl NdjsonSpillWriter {
    pub fn new(path: &str) -> Self {
        Self { path: path.to_string() }
    }

    pub async fn write(&self, finding: &Finding) -> Result<()> {
        let event = SpilledEvent::from_finding(finding.clone());
        let json = serde_json::to_string(&event)?;
        
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .await?;
            
        file.write_all(json.as_bytes()).await?;
        file.write_all(b"\n").await?;
        file.flush().await?;
        
        Ok(())
    }
}
