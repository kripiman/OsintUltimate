use anyhow::Result;
use async_trait::async_trait;
use crate::models::{Finding, AIAnalysis, TargetHost};
use super::types::{CapabilityGap, AdaptiveContext, RouteLevel};

#[async_trait]
pub trait LlmClient: Send + Sync {
    async fn analyze(
        &self, 
        finding: &Finding, 
        target: &TargetHost, 
        attack_context: Option<&str>, 
        route_level: RouteLevel,
        caveman: super::types::CavemanLevel,
    ) -> Result<AIAnalysis>;

    async fn decide_action(
        &self, 
        finding: &Finding, 
        target: &TargetHost,
        plugins: &[crate::plugins::PluginMetadata],
        attack_context: Option<&str>,
        gap: Option<&CapabilityGap>,
        adaptive_context: Option<&AdaptiveContext>,
        route_level: RouteLevel,
        caveman: super::types::CavemanLevel,
    ) -> Result<Option<(String, serde_json::Value)>>;
}
