// src/utils/program_config.rs
// 🎯 V14.2: Per-Program Configuration for Professional Bug Bounty

use serde::{Deserialize, Serialize};
use anyhow::{Result, Context};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramConfig {
    pub name: String,
    pub description: Option<String>,
    pub rate_limit_rps: Option<u32>,
    pub concurrency_override: Option<usize>,
    pub nuclei_custom_templates: Option<String>,
    pub excluded_endpoints: Vec<String>,
    pub custom_headers: Vec<(String, String)>,
    pub reporting_platform: Option<String>, // e.g. "hackerone", "bugcrowd", "intigriti"
}

impl ProgramConfig {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read program config at {:?}", path.as_ref()))?;
        
        let config: ProgramConfig = if path.as_ref().extension().map(|e| e == "json").unwrap_or(false) {
            serde_json::from_str(&content)?
        } else {
            // Assume TOML if not JSON (v14.2 preference)
            toml::from_str(&content)?
        };

        Ok(config)
    }

    /// Generates a default skeleton if not present
    pub fn skeleton(name: &str) -> Self {
        Self {
            name: name.to_string(),
            description: Some("Automated BB program configuration".to_string()),
            rate_limit_rps: Some(5),
            concurrency_override: None,
            nuclei_custom_templates: None,
            excluded_endpoints: vec!["/logout".to_string(), "/delete-account".to_string()],
            custom_headers: vec![("X-Bug-Bounty".to_string(), "Mimikri-Operator".to_string())],
            reporting_platform: None,
        }
    }
}
