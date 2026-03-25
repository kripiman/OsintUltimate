use crate::models::{Finding, AIAnalysis};
use crate::plugins::PluginMetadata;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use crate::core::agent::LlmClient;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RouteLevel {
    Local = 0,   // Ollama / Qwen
    Mid = 1,     // Gemini Flash
    Premium = 2, // Gemini Pro
}

/// Helper to minify findings and plugins to save tokens.
pub struct ContextCompressor;

impl ContextCompressor {
    pub fn compress_finding(finding: &Finding) -> serde_json::Value {
        let mut ev = finding.evidence.data.clone();
        if let Some(obj) = ev.as_object_mut() {
            // Truncate large bodies
            if let Some(body) = obj.get_mut("body") {
                if let Some(s) = body.as_str() {
                    if s.len() > 512 {
                        *body = serde_json::json!(format!("{}... [TRUNCATED]", &s[..512]));
                    }
                }
            }
            // Strip noisy headers, keep security/tech ones
            if let Some(headers) = obj.get_mut("headers") {
                if let Some(h_obj) = headers.as_object_mut() {
                    let whitelist = [
                        "server", "x-powered-by", "content-security-policy", 
                        "x-frame-options", "strict-transport-security", "location",
                        "www-authenticate", "x-content-type-options"
                    ];
                    let keys: Vec<String> = h_obj.keys().cloned().collect();
                    for k in keys {
                        if !whitelist.contains(&k.to_lowercase().as_str()) {
                            h_obj.remove(&k);
                        }
                    }
                }
            }
        }

        serde_json::json!({
            "id": finding.id,
            "sev": finding.severity,
            "cat": finding.category,
            "cvss": finding.cvss_score,
            "desc": finding.description.chars().take(200).collect::<String>(),
            "ev": ev,
        })
    }

    pub fn compress_plugins(plugins: &[PluginMetadata]) -> Vec<serde_json::Value> {
        plugins.iter().map(|p| {
            serde_json::json!({
                "n": p.name,
                "caps": p.capabilities,
                "lyr": p.layer,
            })
        }).collect()
    }
}

/// Orchestrates multiple LLM clients based on task complexity/severity.
pub struct TieredAIRouter {
    pub clients: std::collections::HashMap<RouteLevel, Arc<dyn LlmClient>>,
}

impl TieredAIRouter {
    pub fn new() -> Self {
        Self {
            clients: std::collections::HashMap::new(),
        }
    }

    pub fn add_client(&mut self, level: RouteLevel, client: Arc<dyn LlmClient>) {
        self.clients.insert(level, client);
    }

    /// Primary logic: decides which model tier to use based on finding severity.
    pub fn classify(&self, finding: &Finding) -> RouteLevel {
        let cvss = finding.cvss_score.unwrap_or(0.0);
        if cvss >= 8.5 {
            RouteLevel::Premium
        } else if cvss >= 5.0 {
            RouteLevel::Mid
        } else {
            RouteLevel::Local
        }
    }

    pub async fn analyze(&self, finding: &Finding) -> Result<AIAnalysis> {
        let target_level = self.classify(finding);
        
        // Start from target_level and try higher tiers if failures occur
        for level_val in (target_level as i32)..=2 {
            let current_level = match level_val {
                0 => RouteLevel::Local,
                1 => RouteLevel::Mid,
                2 => RouteLevel::Premium,
                _ => break,
            };

            if let Some(client) = self.clients.get(&current_level) {
                match client.analyze(finding).await {
                    Ok(analysis) => {
                        let mut analysis = analysis;
                        analysis.model = format!("{} (Tiered: {:?})", analysis.model, current_level);
                        return Ok(analysis);
                    }
                    Err(e) => {
                        tracing::warn!("TieredRouter: {:?} analysis failed: {}. Trying next tier...", current_level, e);
                    }
                }
            }
        }
        
        Err(anyhow::anyhow!("All TieredAIRouter analysis attempts failed for finding {}", finding.id))
    }

    pub async fn decide_action(
        &self,
        finding: &Finding,
        plugins: &[PluginMetadata],
    ) -> Result<Option<String>> {
        let target_level = self.classify(finding);
        
        for level_val in (target_level as i32)..=2 {
            let current_level = match level_val {
                0 => RouteLevel::Local,
                1 => RouteLevel::Mid,
                2 => RouteLevel::Premium,
                _ => break,
            };

            if let Some(client) = self.clients.get(&current_level) {
                match client.decide_action(finding, plugins, None).await {
                    Ok(action) => return Ok(action),
                    Err(e) => {
                       tracing::warn!("TieredRouter: {:?} decision failed: {}. Escalating...", current_level, e);
                    }
                }
            }
        }
        
        Ok(None)
    }
}
