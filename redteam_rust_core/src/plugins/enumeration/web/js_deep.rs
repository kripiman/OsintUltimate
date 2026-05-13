use crate::plugins::{ScannerPlugin, Capability, PluginMetadata, RiskLevel, TargetType};
use crate::models::{TargetHost, Finding, Severity, Category};
use crate::core::capability_layer::ScanLayer;
use crate::utils::tool_detection::detect_tool;
use async_trait::async_trait;
use anyhow::Result;
use tracing::info;
use tokio::process::Command;
use std::process::Stdio;

// SubJS: Extract JS files from URLs
pub struct SubJSScanner {
    binary_path: String,
}

impl SubJSScanner {
    pub fn new() -> Self {
        Self { binary_path: detect_tool("subjs") }
    }
}

impl Default for SubJSScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ScannerPlugin for SubJSScanner {
    fn name(&self) -> &'static str { "subjs" }
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: self.name().to_string(),
            description: "Fetches JavaScript files from a list of URLs/domains".to_string(),
            target_type: TargetType::Web,
            risk_level: RiskLevel::Safe,
            layer: ScanLayer::Discovery,
            category: "JS Recon".to_string(),
            expected_duration: std::time::Duration::from_secs(30),
            capabilities: vec![Capability::JsAnalysis],
            cost: 1,
            mitre_attacks: vec!["T1595".to_string()],
            exploit_difficulty: RiskLevel::Low,
            blackarch_category: Some("webapp".to_string()),
            is_destructive: false,
            poc_mode: false, ..Default::default() }
    }
    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::JsAnalysis]
    }
    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability("subjs").await)
    }
    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        info!("SubJSScanner: fetching JS files for {}", target.host);
        let output = Command::new(&self.binary_path)
            .arg("-i")
            .arg(format!("https://{}", target.host))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await?;

        if !output.status.success() {
            return Ok(vec![]);
        }

        let content = String::from_utf8_lossy(&output.stdout);
        let urls: Vec<String> = content.lines().map(|s| s.to_string()).collect();
        
        if urls.is_empty() { return Ok(vec![]); }

        Ok(vec![Finding::new(
            "JS-FILES-DISCOVERED",
            Category::Recon,
            Severity::Info,
            &format!("Discovered {} JS files for {}", urls.len(), target.host),
            serde_json::json!({
                "host": target.host,
                "count": urls.len(),
                "js_urls": urls,
                "tool": "subjs"
            })
        )])
    }
}

// Retire.js: Scan JS for vulnerabilities
pub struct RetireScanner {
    binary_path: String,
}

impl RetireScanner {
    pub fn new() -> Self {
        Self { binary_path: detect_tool("retire") }
    }
}

impl Default for RetireScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ScannerPlugin for RetireScanner {
    fn name(&self) -> &'static str { "retire" }
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: self.name().to_string(),
            description: "Scanner detecting the use of JavaScript libraries with known vulnerabilities".to_string(),
            target_type: TargetType::Web,
            risk_level: RiskLevel::Safe,
            layer: ScanLayer::Scanning,
            category: "JS Recon".to_string(),
            expected_duration: std::time::Duration::from_secs(60),
            capabilities: vec![Capability::JsAnalysis],
            cost: 2,
            mitre_attacks: vec!["T1595".to_string()],
            exploit_difficulty: RiskLevel::Low,
            blackarch_category: Some("webapp".to_string()),
            is_destructive: false,
            poc_mode: true, ..Default::default() }
    }
    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::JsAnalysis]
    }
    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability("retire").await)
    }
    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        info!("RetireScanner: scanning JS libraries for {}", target.host);
        
        let output = Command::new(&self.binary_path)
            .arg("--js")
            .arg("--url")
            .arg(format!("https://{}", target.host))
            .arg("--outputformat")
            .arg("json")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await?;

        let content = String::from_utf8_lossy(&output.stdout);
        if content.trim().is_empty() { return Ok(vec![]); }

        let json_res: serde_json::Value = serde_json::from_str(&content).unwrap_or(serde_json::json!({"raw": content}));
        
        if content.to_lowercase().contains("vulnerability") || content.to_lowercase().contains("vulnerable") {
            return Ok(vec![Finding::new(
                "VULNERABLE-JS-LIBRARY",
                Category::Vulnerability,
                Severity::Medium,
                &format!("Vulnerable JS libraries detected for {}", target.host),
                serde_json::json!({
                    "host": target.host,
                    "report": json_res,
                    "tool": "retire"
                })
            )]);
        }

        Ok(vec![])
    }
}

// SourceMapper: Extract info from JS source maps
pub struct SourceMapperScanner {
    binary_path: String,
}

impl SourceMapperScanner {
    pub fn new() -> Self {
        Self { binary_path: detect_tool("sourcemapper") }
    }
}

impl Default for SourceMapperScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ScannerPlugin for SourceMapperScanner {
    fn name(&self) -> &'static str { "sourcemapper" }
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: self.name().to_string(),
            description: "Extracts information from JavaScript source map files".to_string(),
            target_type: TargetType::Web,
            risk_level: RiskLevel::Safe,
            layer: ScanLayer::Scanning,
            category: "JS Recon".to_string(),
            expected_duration: std::time::Duration::from_secs(45),
            capabilities: vec![Capability::JsAnalysis],
            cost: 2,
            mitre_attacks: vec!["T1595".to_string()],
            exploit_difficulty: RiskLevel::Low,
            blackarch_category: Some("webapp".to_string()),
            is_destructive: false,
            poc_mode: true, ..Default::default() }
    }
    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::JsAnalysis]
    }
    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability("sourcemapper").await)
    }
    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        info!("SourceMapperScanner: looking for source maps for {}", target.host);
        
        let output = Command::new(&self.binary_path)
            .arg("-u")
            .arg(format!("https://{}", target.host))
            .arg("-o")
            .arg("/tmp/sourcemapper_out") 
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await?;

        let content = String::from_utf8_lossy(&output.stdout);
        if content.to_lowercase().contains("extracted") || content.to_lowercase().contains("found") {
             return Ok(vec![Finding::new(
                "JS-SOURCEMAP-EXTRACTED",
                Category::Recon,
                Severity::Low,
                &format!("JS source maps extracted for {}", target.host),
                serde_json::json!({
                    "host": target.host,
                    "tool": "sourcemapper",
                    "note": "Source maps were found and extracted. Check /tmp/sourcemapper_out"
                })
            )]);
        }

        Ok(vec![])
    }
}
