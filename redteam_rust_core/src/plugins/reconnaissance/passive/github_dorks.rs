use crate::plugins::{ScannerPlugin, PluginMetadata, Capability, RiskLevel, GlobalConfig};
use crate::models::{TargetHost, Finding, Category, Severity};
use crate::utils::executor::ExecutorMode;
use async_trait::async_trait;
use anyhow::Result;
use tracing::info;

pub struct GitHubDorksScanner<M: ExecutorMode> {
    config: GlobalConfig<M>,
}

impl<M: ExecutorMode> GitHubDorksScanner<M> {
    pub fn new(config: GlobalConfig<M>) -> Self {
        Self { config }
    }
}

#[async_trait]
impl<M: ExecutorMode> ScannerPlugin for GitHubDorksScanner<M> {
    fn name(&self) -> &'static str { "github-dorks" }

    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: "GitHub Dorks".to_string(),
            description: "Automated GitHub dorking for sensitive data leaks.".to_string(),
            risk_level: RiskLevel::Safe,
            category: "OSINT".to_string(),
            capabilities: vec![Capability::OsintDiscovery, Capability::SecretDiscovery],
            ..Default::default()
        }
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::OsintDiscovery, Capability::SecretDiscovery]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        // Checking for gitdorks_go or similar
        Ok(crate::utils::tool_detection::check_tool_availability("gitdorks_go").await)
    }

    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        let domain = &target.host;
        info!("🔍 Starting GitHub Dorking for {}", domain);

        let mut findings = Vec::new();
        
        // Command construction for gitdorks_go
        let args = vec![
            "-target".to_string(), domain.clone(),
            "-tf".to_string(), "dorks.txt".to_string(), // This assumes a dorks file exists
            "-output".to_string(), "json".to_string(),
        ];

        match self.config.executor.execute_and_wait("gitdorks_go", args).await {
            Ok(output) if output.status.success() => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                // Parsing logic would go here
                // For now, if we found anything, we report a generic finding
                if !stdout.is_empty() {
                    findings.push(Finding::new(
                        "GITHUB-DORK-MATCH",
                        Category::CredentialLeak,
                        Severity::High,
                        &format!("GitHub dorks matched for {}", domain),
                        serde_json::json!({ "output": stdout })
                    ));
                }
            },
            _ => {
                // Tool likely not installed or failed
            }
        }

        Ok(findings)
    }
}
