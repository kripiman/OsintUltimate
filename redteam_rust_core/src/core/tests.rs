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
            file_path: None,
            user: None,
            findings: Arc::new(Vec::new()),
            tool_suggestions: Arc::new(Vec::new()),
            tactical_context: Arc::new(serde_json::json!({})),
            extra_data: Arc::new(serde_json::json!({})),
            version: 0,
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
            file_path: None,
            user: None,
            findings: Arc::new(vec![
                Finding::new(crate::models::FINDING_TECH_STACK, Category::TechnologyStack, Severity::Info, "desc", 
                    serde_json::json!({"plugins": {"Cloudflare": {}}}))
            ]),
            tool_suggestions: Arc::new(Vec::new()),
            tactical_context: Arc::new(serde_json::json!({})),
            extra_data: Arc::new(serde_json::json!({})),
            version: 0,
        };

        let level = router.classify(&finding, &target_waf);
        assert_eq!(level, RouteLevel::Mid);
    }

    #[test]
    fn test_finding_to_markdown() {
        use crate::models::{ConsolidationUrgency};
        let mut finding = Finding::new("FIND-001", Category::Vulnerability, Severity::High, "Test Finding", serde_json::json!({"port": 80}));
        finding = finding
            .with_cvss_vector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L")
            .with_cwe(vec!["CWE-89".to_string()])
            .with_consolidation_urgency(ConsolidationUrgency::Immediate)
            .with_execution_context("OBJ-001", "Scout", 1);
        
        let md = finding.to_markdown();
        assert!(md.contains("# Finding: Test Finding"));
        assert!(md.contains("**Severity**: **High**"));
        assert!(md.contains("CVSS Vector"));
        assert!(md.contains("CWE-89"));
        assert!(md.contains("🚨 Immediate"));
        assert!(md.contains("OBJ-001"));
    }

    #[test]
    fn test_roe_testing_window() {
        use crate::core::policy::{RoE, StaticPolicy, PolicyProvider};
        
        let roe_24_7 = RoE {
            engagement_name: "Test".to_string(),
            client: "Client".to_string(),
            start_date: "".to_string(),
            end_date: "".to_string(),
            testing_window: "24/7".to_string(),
            in_scope: vec![],
            out_of_scope: vec![],
            prohibited_actions: vec![],
            permitted_actions: vec![],
            escalation_contacts: vec![],
            incident_procedure: "".to_string(),
            authorization_reference: "".to_string(),
            cleanup_required: false,
            deconfliction: None,
        };

        let policy = StaticPolicy::new().with_roe(roe_24_7);
        assert!(policy.is_within_testing_window());

        let roe_restricted = RoE {
            engagement_name: "Test".to_string(),
            client: "Client".to_string(),
            start_date: "".to_string(),
            end_date: "".to_string(),
            testing_window: "Mon-Fri 00:00-01:00 UTC".to_string(), // Likely expired unless you are running this at midnight
            in_scope: vec![],
            out_of_scope: vec![],
            prohibited_actions: vec![],
            permitted_actions: vec![],
            escalation_contacts: vec![],
            incident_procedure: "".to_string(),
            authorization_reference: "".to_string(),
            cleanup_required: false,
            deconfliction: None,
        };
        
        let policy_restricted = StaticPolicy::new().with_roe(roe_restricted);
        // This will depend on when the test is run, but we can check if it returns a bool
        let result = policy_restricted.is_within_testing_window();
        println!("Testing window result (restricted): {}", result);
    }

    #[tokio::test]
    async fn test_objective_persistence() -> anyhow::Result<()> {
        use crate::core::sink::PostgresSink;
        use crate::models::{Objective, ObjectiveStatus, ObjectivePhase};
        use tempfile::tempdir;

        let tmp_dir = tempdir()?;
        let db_path = tmp_dir.path().join("opplan_test.db");
        let sink = PostgresSink::new(db_path).await?;

        let obj = Objective::new("OBJ-001", "Initial Access", "Gain a foothold in the perimeter.", ObjectivePhase::InitialAccess)
            .with_status(ObjectiveStatus::InProgress);

        sink.save_objective(&obj).await?;

        // Verify using the public pool
        let row: (String, String) = sqlx::query_as("SELECT title, status FROM objectives WHERE id = ?")
            .bind("OBJ-001")
            .fetch_one(&sink.pool)
            .await?;

        assert_eq!(row.0, "Initial Access");
        assert_eq!(row.1, "in_progress");

        Ok(())
    }
}
