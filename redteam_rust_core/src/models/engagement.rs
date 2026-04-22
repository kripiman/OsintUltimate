use serde::{Deserialize, Serialize};
use anyhow::Result;
use std::path::Path;
use crate::models::objectives::OPPLAN;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngagementState {
    pub engagement_id: String,
    pub mission_name: String,
    pub start_time: chrono::DateTime<chrono::Utc>,
    pub last_updated: chrono::DateTime<chrono::Utc>,
    pub opplan: OPPLAN,
    pub tokens_consumed: u32,
    pub targets_processed: Vec<String>,
}

impl EngagementState {
    pub fn new(id: &str, mission_name: &str) -> Self {
        let now = chrono::Utc::now();
        Self {
            engagement_id: id.to_string(),
            mission_name: mission_name.to_string(),
            start_time: now,
            last_updated: now,
            opplan: OPPLAN::new(),
            tokens_consumed: 0,
            targets_processed: Vec::new(),
        }
    }

    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }

    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let state = serde_json::from_str(&content)?;
        Ok(state)
    }

    pub fn update_tokens(&mut self, consumed: u32) {
        self.tokens_consumed += consumed;
        self.last_updated = chrono::Utc::now();
    }

    pub fn add_target(&mut self, host: &str) {
        if !self.targets_processed.contains(&host.to_string()) {
            self.targets_processed.push(host.to_string());
        }
        self.last_updated = chrono::Utc::now();
    }
}
