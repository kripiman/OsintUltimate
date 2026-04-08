use crate::core::sink::{DataSink, MultiSink};
use crate::models::{TargetHost, TargetType, TargetStatus, Finding, Category, Severity};
use crate::core::ai::{TieredAIRouter, RouteLevel};
use anyhow::Result;
use std::sync::Arc;

#[cfg(test)]
mod tests {
    use super::*;

    struct MockSink;

    #[async_trait::async_trait]
    impl DataSink for MockSink {
        async fn write(&mut self, _: &TargetHost) -> Result<()> { Ok(()) }
        async fn write_metadata(&mut self, _: &crate::models::ScanMetadata) -> Result<()> { Ok(()) }
        async fn close(&mut self) -> Result<()> { Ok(()) }
    }

    #[tokio::test]
    async fn test_multi_sink_logic() -> Result<()> {
        let mut multi = MultiSink::new();
        multi.add(Box::new(MockSink));
        
        let target = TargetHost {
            host: "test.local".to_string(),
            ip: None,
            resolved_ip: None,
            status: TargetStatus::Pending,
            target_type: TargetType::Host,
            findings: Arc::new(Vec::new()),
            tool_suggestions: Arc::new(Vec::new()),
            tactical_context: Arc::new(serde_json::json!({})),
            extra_data: Arc::new(serde_json::json!({})),
        };

        multi.write(&target).await?;
        Ok(())
    }

    #[test]
    fn test_ai_waf_escalation() {
        let router = TieredAIRouter::new();
        let finding = Finding::new("TEST", Category::Vulnerability, Severity::Low, "desc", serde_json::json!({}));
        
        // Target WITH WAF in tech stack
        let target_waf = TargetHost {
            host: "waf.com".to_string(),
            ip: None,
            resolved_ip: None,
            status: TargetStatus::Pending,
            target_type: TargetType::Web,
            findings: Arc::new(vec![
                Finding::new(crate::models::FINDING_TECH_STACK, Category::TechnologyStack, Severity::Info, "desc", 
                    serde_json::json!({"plugins": {"Cloudflare": {}}}))
            ]),
            tool_suggestions: Arc::new(Vec::new()),
            tactical_context: Arc::new(serde_json::json!({})),
            extra_data: Arc::new(serde_json::json!({})),
        };

        let level = router.classify(&finding, &target_waf);
        assert_eq!(level, RouteLevel::Mid);
    }
}
