use crate::plugins::Capability;
use anyhow::{Result, Context};
use moka::future::Cache;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tracing::{info, warn};

// ─────────────────────────────────────────────────────────────────────────────
// BLACKARCH TOOL DEFINITIONS
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlackArchTool {
    pub name: String,
    pub category: String,
    pub description: String,
    pub capabilities: Vec<Capability>,
}

// ─────────────────────────────────────────────────────────────────────────────
// STRUCTURED DISTILLATION: TOOL SCHEMA TYPES
// ─────────────────────────────────────────────────────────────────────────────

/// Normalized schema extracted from a tool's --help output.
/// This is the structured representation that gets injected into LLM context
/// instead of raw text, saving tokens and reducing hallucination.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSchema {
    pub tool_name: String,
    pub version: Option<String>,
    /// One-line synopsis extracted from the first line of --help
    pub synopsis: String,
    /// Parsed CLI flags with their descriptions
    pub flags: Vec<FlagSchema>,
    /// Detected output formats (json, xml, csv, etc.)
    pub output_formats: Vec<String>,
    /// Estimated resource cost based on tool category
    pub resource_cost: ResourceCost,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlagSchema {
    /// Short form, e.g., "-p"
    pub short: Option<String>,
    /// Long form, e.g., "--ports"
    pub long: Option<String>,
    /// Description of what the flag does
    pub description: String,
    /// Whether the flag expects a value argument
    pub takes_value: bool,
    /// Default value if documented
    pub default_value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ResourceCost {
    /// OSINT/recon tools, fast lookups
    Light,
    /// Web scanners, moderate network usage
    Medium,
    /// Full port scans, brute-force, heavy Network/CPU
    Heavy,
}

// ─────────────────────────────────────────────────────────────────────────────
// BLACKARCH BRIDGE (Original + Distillation)
// ─────────────────────────────────────────────────────────────────────────────

pub struct BlackArchBridge {
    pub tools: HashMap<String, BlackArchTool>,
    pub available_tools: HashSet<String>,
    /// Moka cache for distilled schemas (24h TTL)
    schema_cache: Cache<String, ToolSchema>,
    /// Semaphore to limit concurrent --help subprocess calls (backpressure)
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
            BlackArchTool {
                name: "sqlmap".to_string(),
                category: "webapp".to_string(),
                description: "Automatic SQL injection and database takeover tool".to_string(),
                capabilities: vec![Capability::SqlInjection, Capability::VulnerabilityScanning, Capability::ApiSecurity],
            },
            BlackArchTool {
                name: "nmap".to_string(),
                category: "scanner".to_string(),
                description: "Network exploration tool and security / port scanner".to_string(),
                capabilities: vec![Capability::PortScanning, Capability::ServiceDiscovery],
            },
            BlackArchTool {
                name: "nuclei".to_string(),
                category: "scanner".to_string(),
                description: "Fast and customizable vulnerability scanner based on simple YAML based templates".to_string(),
                capabilities: vec![Capability::VulnerabilityScanning, Capability::WebFuzzing],
            },
            BlackArchTool {
                name: "hydra".to_string(),
                category: "cracker".to_string(),
                description: "Network logon cracker which supports many different services".to_string(),
                capabilities: vec![Capability::BruteForce], 
            },
            BlackArchTool {
                name: "dalfox".to_string(),
                category: "webapp".to_string(),
                description: "Parameter Analysis and XSS Scanning tool based on golang".to_string(),
                capabilities: vec![Capability::XssScanning, Capability::VulnerabilityScanning],
            },
            BlackArchTool {
                name: "commix".to_string(),
                category: "exploitation".to_string(),
                description: "Automated All-in-One OS Command Injection and Exploitation Tool".to_string(),
                capabilities: vec![Capability::CommandInjection, Capability::VulnerabilityScanning], 
            },
            BlackArchTool {
                name: "graphql-cop".to_string(),
                category: "webapp".to_string(),
                description: "GraphQL security auditor".to_string(),
                capabilities: vec![Capability::VulnerabilityScanning, Capability::GraphQL],
            },
        ];

        let mut available_tools = HashSet::new();
        for tool in popular_tools {
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
                .time_to_live(Duration::from_secs(86400)) // 24h TTL
                .build(),
            distill_semaphore: Arc::new(Semaphore::new(3)), // Max 3 concurrent --help calls
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

    // ─────────────────────────────────────────────────────────────────────
    // STRUCTURED DISTILLATION ENGINE
    // ─────────────────────────────────────────────────────────────────────

    /// Runs `tool --help` asynchronously and parses the output into a ToolSchema.
    /// Uses tokio::process with a 10-second hard timeout and semaphore-limited
    /// concurrency (max 3 simultaneous subprocess invocations).
    ///
    /// Results are cached in moka for 24h to avoid redundant subprocess calls.
    pub async fn distill_schema(&self, tool_name: &str) -> Result<ToolSchema> {
        // 1. Check cache first
        let cache_key = tool_name.to_string();
        if let Some(cached) = self.schema_cache.get(&cache_key) {
            return Ok(cached);
        }

        // 2. Verify tool exists
        if !self.is_tool_installed(tool_name) {
            anyhow::bail!("Tool '{}' is not installed on this system", tool_name);
        }

        // 3. Acquire semaphore permit (backpressure — max 3 concurrent calls)
        let _permit = self.distill_semaphore.acquire().await
            .map_err(|_| anyhow::anyhow!("Distill semaphore closed"))?;

        info!("📐 DISTILL: Extracting schema for '{}'...", tool_name);

        // 4. Run `tool --help` with a 10-second hard timeout
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

        // Many tools write help to stderr, so combine both
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let help_text = if stdout.len() > stderr.len() { stdout.to_string() } else { stderr.to_string() };

        if help_text.is_empty() {
            anyhow::bail!("'{}' --help produced no output", tool_name);
        }

        // 5. Parse the help text into a ToolSchema
        let schema = Self::parse_help_output(tool_name, &help_text, self.tools.get(tool_name));

        // 6. Cache the result
        self.schema_cache.insert(cache_key, schema.clone()).await;

        info!("📐 DISTILL: Schema for '{}' → {} flags, formats: {:?}, cost: {:?}",
            tool_name, schema.flags.len(), schema.output_formats, schema.resource_cost);

        Ok(schema)
    }

    /// Batch distill schemas for all available tools with concurrency limiting.
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

    /// Converts distilled schemas into a minimal JSON blob optimized for AI context injection.
    /// This replaces raw tool descriptions in LLM prompts with structured data.
    pub fn schemas_to_ai_context(schemas: &[ToolSchema]) -> serde_json::Value {
        let tools: Vec<serde_json::Value> = schemas.iter().map(|s| {
            let flags_summary: Vec<serde_json::Value> = s.flags.iter()
                .take(15) // Cap at 15 flags per tool to control token usage
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

    // ─────────────────────────────────────────────────────────────────────
    // INTERNAL: HELP TEXT PARSER
    // ─────────────────────────────────────────────────────────────────────

    fn parse_help_output(tool_name: &str, help_text: &str, tool_info: Option<&BlackArchTool>) -> ToolSchema {
        let lines: Vec<&str> = help_text.lines().collect();

        // Extract synopsis (first non-empty line, often the tool description)
        let synopsis = lines.iter()
            .find(|l| !l.trim().is_empty())
            .map(|l| l.trim().to_string())
            .unwrap_or_else(|| tool_info.map(|t| t.description.clone()).unwrap_or_default());

        // Extract version (look for patterns like "v1.2.3", "version 1.2", etc.)
        let version_re = Regex::new(r"(?i)(?:v(?:ersion)?\s*)?(\d+\.\d+(?:\.\d+)?)").ok();
        let version = version_re.and_then(|re| {
            lines.iter()
                .take(5) // Version is usually in the first 5 lines
                .find_map(|l| re.find(l).map(|m| m.as_str().to_string()))
        });

        // Parse flags using two regex patterns
        let mut flags = Vec::new();

        // Pattern 1: -s, --long-flag  Description text
        let flag_re_combined = Regex::new(r"^\s+(-\w),?\s*(--[\w-]+)\s+(.+)").ok();
        // Pattern 2: --long-flag  Description text (no short form)
        let flag_re_long = Regex::new(r"^\s+(--[\w-]+)\s+(.+)").ok();
        // Pattern 3: -s  Description text (short only, 2+ spaces before desc)
        let flag_re_short = Regex::new(r"^\s+(-\w)\s{2,}(.+)").ok();
        // Pattern 4: -s <VALUE>  Description (short flag with value placeholder)
        let flag_re_short_val = Regex::new(r"^\s+(-\w)\s+(<[^>]+>)\s{2,}(.+)").ok();

        for line in &lines {
            // Try combined pattern first
            if let Some(ref re) = flag_re_combined {
                if let Some(caps) = re.captures(line) {
                    let desc = caps.get(3).map(|m| m.as_str().trim().to_string()).unwrap_or_default();
                    flags.push(FlagSchema {
                        short: caps.get(1).map(|m| m.as_str().to_string()),
                        long: caps.get(2).map(|m| m.as_str().to_string()),
                        description: desc.clone(),
                        takes_value: Self::flag_takes_value(&desc, line),
                        default_value: Self::extract_default(&desc),
                    });
                    continue;
                }
            }

            // Try long-only pattern
            if let Some(ref re) = flag_re_long {
                if let Some(caps) = re.captures(line) {
                    let desc = caps.get(2).map(|m| m.as_str().trim().to_string()).unwrap_or_default();
                    flags.push(FlagSchema {
                        short: None,
                        long: caps.get(1).map(|m| m.as_str().to_string()),
                        description: desc.clone(),
                        takes_value: Self::flag_takes_value(&desc, line),
                        default_value: Self::extract_default(&desc),
                    });
                    continue;
                }
            }

            // Try short-only pattern
            if let Some(ref re) = flag_re_short {
                if let Some(caps) = re.captures(line) {
                    let desc = caps.get(2).map(|m| m.as_str().trim().to_string()).unwrap_or_default();
                    flags.push(FlagSchema {
                        short: caps.get(1).map(|m| m.as_str().to_string()),
                        long: None,
                        description: desc.clone(),
                        takes_value: Self::flag_takes_value(&desc, line),
                        default_value: Self::extract_default(&desc),
                    });
                    continue;
                }
            }

            // Try short flag with value placeholder: -p <port ranges>  Description
            if let Some(ref re) = flag_re_short_val {
                if let Some(caps) = re.captures(line) {
                    let desc = caps.get(3).map(|m| m.as_str().trim().to_string()).unwrap_or_default();
                    flags.push(FlagSchema {
                        short: caps.get(1).map(|m| m.as_str().to_string()),
                        long: None,
                        description: desc.clone(),
                        takes_value: true, // Always takes value if <PLACEHOLDER> is present
                        default_value: Self::extract_default(&desc),
                    });
                }
            }
        }

        // Detect output format support
        let help_lower = help_text.to_lowercase();
        let mut output_formats = Vec::new();
        for fmt in &["json", "xml", "csv", "html", "yaml", "greppable"] {
            if help_lower.contains(fmt) {
                output_formats.push(fmt.to_string());
            }
        }

        // Classify resource cost based on category
        let resource_cost = tool_info
            .map(|t| match t.category.as_str() {
                "scanner" => ResourceCost::Heavy,
                "cracker" => ResourceCost::Heavy,
                "exploitation" => ResourceCost::Heavy,
                "webapp" => ResourceCost::Medium,
                "fuzzer" => ResourceCost::Medium,
                _ => ResourceCost::Light,
            })
            .unwrap_or(ResourceCost::Medium);

        ToolSchema {
            tool_name: tool_name.to_string(),
            version,
            synopsis,
            flags,
            output_formats,
            resource_cost,
        }
    }

    /// Heuristic: a flag likely takes a value if the description mentions
    /// placeholders like <VALUE>, FILE, NUM, etc.
    fn flag_takes_value(desc: &str, line: &str) -> bool {
        let indicators = ["<", ">", "FILE", "PATH", "NUM", "PORT", "URL", "HOST", "="];
        indicators.iter().any(|i| desc.to_uppercase().contains(i) || line.contains(i))
    }

    /// Extract default value from description text like "(default: 80)" or "[default: 10]"
    fn extract_default(desc: &str) -> Option<String> {
        let re = Regex::new(r"(?i)(?:\(|\[)default[:\s]+([^\)\]]+)(?:\)|\])").ok()?;
        re.captures(desc).and_then(|c| c.get(1).map(|m| m.as_str().trim().to_string()))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TESTS
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_help_output_extracts_flags() {
        let mock_help = r#"Nmap 7.93 ( https://nmap.org )
Usage: nmap [Scan Type(s)] [Options] {target specification}

HOST DISCOVERY:
  -sL             List Scan - simply list targets to scan
  -sn             Ping Scan - disable port scan
  -Pn             Treat all hosts as online
  -PS/PA/PU/PY   TCP SYN/ACK, UDP or SCTP discovery to given ports
  -PE/PP/PM       ICMP echo, timestamp, and netmask request

PORT SPECIFICATION AND SCAN ORDER:
  -p <port ranges>    Only scan specified ports (default: 1-1024)
  -F                  Fast mode - Scan fewer ports than the default scan

OUTPUT:
  -oN/-oX/-oS/-oG <file>  Output scan in normal, XML, greppable
  -oA <basename>      Output in the three major formats at once
  --open              Only show open ports
  -v                  Increase verbosity level (use -vv or more for greater effect)
  --reason            Display the reason a port is in a particular state
"#;

        let tool_info = BlackArchTool {
            name: "nmap".to_string(),
            category: "scanner".to_string(),
            description: "Network exploration tool".to_string(),
            capabilities: vec![Capability::PortScanning],
        };

        let schema = BlackArchBridge::parse_help_output("nmap", mock_help, Some(&tool_info));

        assert_eq!(schema.tool_name, "nmap");
        assert!(schema.version.is_some());
        assert!(!schema.flags.is_empty(), "Should have extracted at least some flags");
        assert!(schema.output_formats.contains(&"xml".to_string()));
        assert!(schema.output_formats.contains(&"greppable".to_string()));
        assert_eq!(schema.resource_cost, ResourceCost::Heavy);

        // Check that -p flag was parsed with takes_value=true
        let port_flag = schema.flags.iter().find(|f| f.short.as_deref() == Some("-p"));
        assert!(port_flag.is_some(), "Should have extracted -p flag");
        if let Some(pf) = port_flag {
            assert!(pf.takes_value, "-p should take a value");
        }
    }

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

    #[test]
    fn test_extract_default_value() {
        assert_eq!(
            BlackArchBridge::extract_default("Specify ports (default: 1-1024)"),
            Some("1-1024".to_string())
        );
        assert_eq!(
            BlackArchBridge::extract_default("Set timeout [Default: 30]"),
            Some("30".to_string())
        );
        assert_eq!(
            BlackArchBridge::extract_default("Enable verbose mode"),
            None
        );
    }

    #[test]
    fn test_flag_takes_value_heuristic() {
        assert!(BlackArchBridge::flag_takes_value("Specify <PORT> to scan", "  -p <PORT>"));
        assert!(BlackArchBridge::flag_takes_value("Output FILE path", "  -o FILE"));
        assert!(!BlackArchBridge::flag_takes_value("Enable verbose mode", "  -v  Enable verbose mode"));
    }

    #[test]
    fn test_resource_cost_classification() {
        let scanner = BlackArchTool {
            name: "nmap".to_string(),
            category: "scanner".to_string(),
            description: "".to_string(),
            capabilities: vec![],
        };
        let schema = BlackArchBridge::parse_help_output("nmap", "nmap help", Some(&scanner));
        assert_eq!(schema.resource_cost, ResourceCost::Heavy);

        let webapp = BlackArchTool {
            name: "sqlmap".to_string(),
            category: "webapp".to_string(),
            description: "".to_string(),
            capabilities: vec![],
        };
        let schema2 = BlackArchBridge::parse_help_output("sqlmap", "sqlmap help", Some(&webapp));
        assert_eq!(schema2.resource_cost, ResourceCost::Medium);
    }
}

