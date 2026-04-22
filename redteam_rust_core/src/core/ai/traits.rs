use anyhow::Result;
use async_trait::async_trait;
use crate::models::{Finding, AIAnalysis, TargetHost};
use super::types::{CapabilityGap, AdaptiveContext, RouteLevel};

pub struct InferenceConfig<'a> {
    pub finding: &'a Finding,
    pub target: &'a TargetHost,
    pub attack_context: Option<&'a str>,
    pub route_level: RouteLevel,
    pub caveman: super::types::CavemanLevel,
}

pub struct DecisionConfig<'a> {
    pub finding: &'a Finding,
    pub target: &'a TargetHost,
    pub plugins: &'a [crate::plugins::PluginMetadata],
    pub attack_context: Option<&'a str>,
    pub gap: Option<&'a CapabilityGap>,
    pub adaptive_context: Option<&'a AdaptiveContext>,
    pub route_level: RouteLevel,
    pub caveman: super::types::CavemanLevel,
}

#[async_trait]
pub trait LlmClient: Send + Sync {
    async fn analyze(&self, config: InferenceConfig<'_>) -> Result<AIAnalysis>;

    async fn decide_action(&self, config: DecisionConfig<'_>) -> Result<Option<(String, serde_json::Value)>>;
}
