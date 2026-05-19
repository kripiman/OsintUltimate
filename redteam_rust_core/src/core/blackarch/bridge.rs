use crate::plugins::Capability;
use super::schema::{BlackArchTool, ToolSchema};
use super::parser::parse_help_output;
use anyhow::{Result, Context};
use moka::future::Cache;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tracing::{info, warn};

pub struct BlackArchBridge {
    pub tools: HashMap<String, BlackArchTool>,
    pub available_tools: HashSet<String>,
    schema_cache: Cache<String, ToolSchema>,
    distill_semaphore: Arc<Semaphore>,
}

impl Default for BlackArchBridge {
    fn default() -> Self {
        Self::new()
    }
}

impl BlackArchBridge {
    pub fn new() -> Self {
        let mut tools = HashMap::new();
        let popular_tools = vec![
            ("sqlmap", "webapp", "Automatic SQL injection and database takeover tool", vec![Capability::SqlInjection, Capability::VulnerabilityScanning, Capability::ApiSecurity]),
            ("nmap", "scanner", "Network exploration tool and security / port scanner", vec![Capability::PortScanning, Capability::ServiceDiscovery]),
            ("nuclei", "scanner", "Fast and customizable vulnerability scanner based on simple YAML based templates", vec![Capability::VulnerabilityScanning, Capability::WebFuzzing]),
            ("hydra", "cracker", "Network logon cracker which supports many different services", vec![Capability::BruteForce]),
            ("dalfox", "webapp", "Parameter Analysis and XSS Scanning tool based on golang", vec![Capability::XssScanning, Capability::VulnerabilityScanning]),
            ("commix", "exploitation", "Automated All-in-One OS Command Injection and Exploitation Tool", vec![Capability::CommandInjection, Capability::VulnerabilityScanning]),
            ("graphql-cop", "webapp", "GraphQL security auditor", vec![Capability::VulnerabilityScanning, Capability::GraphQL]),
        ];

        let mut available_tools = HashSet::new();
        for (name, category, description, capabilities) in popular_tools {
            let tool = BlackArchTool {
                name: name.to_string(),
                category: category.to_string(),
                description: description.to_string(),
                capabilities,
            };
            if which::which(&tool.name).is_ok() {
                available_tools.insert(tool.name.clone());
            }
            tools.insert(tool.name.clone(), tool);
        }

        Self {
            tools,
            available_tools,
            schema_cache: Cache::builder()
                .max_capacity(500)
                .time_to_live(Duration::from_secs(86400))
                .build(),
            distill_semaphore: Arc::new(Semaphore::new(3)),
        }
    }

    pub fn is_tool_installed(&self, tool_name: &str) -> bool {
        self.available_tools.contains(tool_name)
    }

    pub fn get_available_tools(&self) -> Vec<&BlackArchTool> {
        self.tools.values()
            .filter(|t| self.is_tool_installed(&t.name))
            .collect()
    }

    pub fn suggest_tools_for_capability(&self, capability: Capability) -> Vec<&BlackArchTool> {
        self.tools.values()
            .filter(|t| t.capabilities.contains(&capability) && self.is_tool_installed(&t.name))
            .collect()
    }

    pub async fn distill_schema(&self, tool_name: &str) -> Result<ToolSchema> {
        let cache_key = tool_name.to_string();
        if let Some(cached) = self.schema_cache.get(&cache_key) {
            return Ok(cached);
        }
        if !self.is_tool_installed(tool_name) {
            anyhow::bail!("Tool '{}' is not installed on this system", tool_name);
        }
        let _permit = self.distill_semaphore.acquire().await
            .map_err(|_| anyhow::anyhow!("Distill semaphore closed"))?;

        info!("📐 DISTILL: Extracting schema for '{}'...", tool_name);
        let output = tokio::time::timeout(
            Duration::from_secs(10),
            tokio::process::Command::new(tool_name)
                .arg("--help")
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .output()
        ).await
            .context(format!("Timeout: '{}' --help took longer than 10s", tool_name))?
            .context(format!("Failed to execute '{}' --help", tool_name))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let help_text = if stdout.len() > stderr.len() { stdout.to_string() } else { stderr.to_string() };

        if help_text.is_empty() {
            anyhow::bail!("'{}' --help produced no output", tool_name);
        }

        let schema = parse_help_output(tool_name, &help_text, self.tools.get(tool_name));
        self.schema_cache.insert(cache_key, schema.clone()).await;
        info!("📐 DISTILL: Schema for '{}' → {} flags, formats: {:?}, cost: {:?}",
            tool_name, schema.flags.len(), schema.output_formats, schema.resource_cost);

        Ok(schema)
    }

    pub async fn distill_all_schemas(&self) -> Vec<ToolSchema> {
        let tool_names: Vec<String> = self.available_tools.iter().cloned().collect();
        let mut schemas = Vec::new();
        for name in tool_names {
            match self.distill_schema(&name).await {
                Ok(schema) => schemas.push(schema),
                Err(e) => warn!("📐 DISTILL: Failed for '{}': {}", name, e),
            }
        }
        schemas
    }

    pub fn schemas_to_ai_context(schemas: &[ToolSchema]) -> serde_json::Value {
        let tools: Vec<serde_json::Value> = schemas.iter().map(|s| {
            let flags_summary: Vec<serde_json::Value> = s.flags.iter()
                .take(15)
                .map(|f| {
                    serde_json::json!({
                        "flag": f.long.as_deref().or(f.short.as_deref()).unwrap_or("?"),
                        "desc": f.description.chars().take(80).collect::<String>(),
                        "val": f.takes_value,
                    })
                })
                .collect();

            serde_json::json!({
                "tool": s.tool_name,
                "syn": s.synopsis.chars().take(120).collect::<String>(),
                "flags": flags_summary,
                "out_fmt": s.output_formats,
                "cost": format!("{:?}", s.resource_cost),
            })
        }).collect();

        serde_json::json!({ "blackarch_tools": tools })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::blackarch::schema::{FlagSchema, ResourceCost};

    #[test]
    fn test_schemas_to_ai_context_format() {
        let schema = ToolSchema {
            tool_name: "nmap".to_string(),
            version: Some("7.93".to_string()),
            synopsis: "Network scanner".to_string(),
            flags: vec![
                FlagSchema {
                    short: Some("-p".to_string()),
                    long: Some("--ports".to_string()),
                    description: "Specify ports to scan".to_string(),
                    takes_value: true,
                    default_value: Some("1-1024".to_string()),
                },
            ],
            output_formats: vec!["json".to_string(), "xml".to_string()],
            resource_cost: ResourceCost::Heavy,
        };

        let ctx = BlackArchBridge::schemas_to_ai_context(&[schema]);
        let tools = ctx["blackarch_tools"].as_array().unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["tool"], "nmap");
        assert!(!tools[0]["flags"].as_array().unwrap().is_empty());
    }
}
