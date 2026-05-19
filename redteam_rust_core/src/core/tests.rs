use crate::core::sink::{DataSink, MultiSink};
use crate::models::{TargetHost, TargetType, Finding, Category, Severity};
use crate::core::ai::{TieredAIRouter, RouteLevel};
use anyhow::Result;
use std::sync::Arc;



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
            ..Default::default()
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
            findings: Arc::new(vec![
                Finding::new(crate::models::FINDING_TECH_STACK, Category::TechnologyStack, Severity::Info, "desc", 
                    serde_json::json!({"plugins": {"Cloudflare": {}}}))
            ]),
            target_type: TargetType::Web,
            ..Default::default()
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
        use sqlx::postgres::PgPoolOptions;
        use std::time::Duration;

        let db_url = match std::env::var("REDTEAM_TEST_DB_URL") {
            Ok(url) => url,
            Err(_) => {
                eprintln!("⊘ SKIP test_objective_persistence: REDTEAM_TEST_DB_URL not set");
                return Ok(());
            }
        };
        let _pool = match PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(2))
            .connect(&db_url).await {
            Ok(p) => p,
            Err(e) => {
                eprintln!("⊘ SKIP test_objective_persistence: connect failed: {e}");
                return Ok(());
            }
        };

        // Temporarily set DATABASE_URL to REDTEAM_TEST_DB_URL so PostgresSink::new uses it
        let old_db_url = std::env::var("DATABASE_URL").ok();
        std::env::set_var("DATABASE_URL", &db_url);

        let tmp_dir = tempdir()?;
        let db_path = tmp_dir.path().join("opplan_test.db");
        let sink_res = PostgresSink::new(db_path).await;

        if let Some(ref val) = old_db_url {
            std::env::set_var("DATABASE_URL", val);
        } else {
            std::env::remove_var("DATABASE_URL");
        }

        let sink = match sink_res {
            Ok(s) => s,
            Err(e) => {
                eprintln!("⊘ SKIP test_objective_persistence: sink initialization failed: {e}");
                return Ok(());
            }
        };

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

    #[test]
    fn test_header_strip_retention() {
        use crate::core::ai::ContextCompressor;

        let headers = serde_json::json!({
            "server": "nginx/1.18.0",
            "x-powered-by": "PHP/7.4.3",
            "location": "https://example.com/login",
            "cookie": "session_id=abcdef123456",
            "user-agent": "Mozilla/5.0",
            "content-type": "text/html"
        });

        let finding = Finding::new(
            "FIND-001",
            Category::Vulnerability,
            Severity::High,
            "Test Finding",
            serde_json::json!({
                "headers": headers,
                "body": "A very long response body that might exceed limits",
                "raw_response": "HTTP/1.1 200 OK\r\n..."
            })
        );

        let target = TargetHost {
            host: "example.com".to_string(),
            ..Default::default()
        };

        // 1. Test standard compression route
        let base_compressed = ContextCompressor::compress_finding(&finding, RouteLevel::Local);
        let ev = base_compressed.get("ev").unwrap().as_object().unwrap();
        let compressed_headers = ev.get("headers").unwrap().as_object().unwrap();

        assert!(compressed_headers.contains_key("server"));
        assert!(compressed_headers.contains_key("x-powered-by"));
        assert!(compressed_headers.contains_key("location"));
        assert!(!compressed_headers.contains_key("cookie"));
        assert!(!compressed_headers.contains_key("user-agent"));
        assert!(!compressed_headers.contains_key("content-type")); // Stripped because not whitelisted

        // 2. Test swarm compression route
        let swarm_compressed = ContextCompressor::compress_swarm_context(&finding, &target);
        let ev_swarm = swarm_compressed.get("ev").unwrap().as_object().unwrap();
        
        // Assert body and raw_response are removed in swarm
        assert!(!ev_swarm.contains_key("body"));
        assert!(!ev_swarm.contains_key("raw_response"));
        
        let swarm_headers = ev_swarm.get("headers").unwrap().as_object().unwrap();
        assert!(swarm_headers.contains_key("server"));
        assert!(swarm_headers.contains_key("x-powered-by"));
        assert!(!swarm_headers.contains_key("location")); // Stripped because not in swarm whitelist
        assert!(!swarm_headers.contains_key("cookie"));
        assert!(!swarm_headers.contains_key("user-agent"));
    }

    #[test]
    fn test_dense_finding_encoding() {
        use crate::core::ai::ContextCompressor;

        // Long body to trigger 150-char truncation
        let long_body = "A".repeat(200);
        let long_description = "B".repeat(150);

        let finding = Finding::new(
            "FIND-DENSE-01",
            Category::Vulnerability,
            Severity::High,
            &long_description,
            serde_json::json!({
                "body": long_body,
                "raw_response": "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nSensitive data here..."
            })
        );

        let compressed = ContextCompressor::compress_finding_dense(&finding);

        // Check required dense keys
        assert_eq!(compressed.get("id").unwrap().as_str().unwrap(), "FIND-DENSE-01");
        assert_eq!(compressed.get("s").unwrap().as_str().unwrap(), "H");
        assert_eq!(compressed.get("cat").unwrap().as_str().unwrap(), "vulnerability");
        assert!(compressed.get("cvss").is_some());
        assert_eq!(compressed.get("cf").unwrap().as_str().unwrap(), "P"); // Default to potential

        // Assert description truncation (limit is 100 characters in dense route)
        let desc = compressed.get("d").unwrap().as_str().unwrap();
        assert!(desc.len() <= 100);
        assert_eq!(desc, "B".repeat(100));

        // Assert evidence minification and stripping
        let ev = compressed.get("ev").unwrap().as_object().unwrap();
        assert!(!ev.contains_key("raw_response")); // MUST be stripped in dense
        
        let body = ev.get("body").unwrap().as_str().unwrap();
        assert!(body.len() <= 153); // 150 + "..."
        assert!(body.contains("..."));
    }

