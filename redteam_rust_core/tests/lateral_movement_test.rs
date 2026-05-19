use async_trait::async_trait;
use redteam_rust_core::plugins::{ScannerPlugin, PluginMetadata, Capability};
use redteam_rust_core::models::{TargetHost, Finding, Severity, Category};
use redteam_rust_core::models::constants::*;
use redteam_rust_core::core::orchestrator::swarm::inventory::{SwarmInventory, TrustLevel};
use redteam_rust_core::core::reactive_engine;
use redteam_rust_core::core::capability_layer::ScanLayerPolicy;
use redteam_rust_core::core::approval_gate::ApprovalGate;
use dashmap::DashSet;
use std::sync::Arc;
use anyhow::Result;

struct MockNetExec {
    last_injected_cred: Arc<tokio::sync::Mutex<Option<Finding>>>,
}

#[async_trait]
impl ScannerPlugin for MockNetExec {
    fn name(&self) -> &'static str { PLUGIN_NETEXEC }
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: self.name().to_string(),
            capabilities: vec![Capability::BruteForce],
            ..Default::default()
        }
    }
    fn capabilities(&self) -> Vec<Capability> { vec![Capability::BruteForce] }
    async fn check_dependencies(&self) -> Result<bool> { Ok(true) }
    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        if let Some(cred_val) = target.extra_data.get("injected_credential") {
            if let Ok(finding) = serde_json::from_value::<Finding>(cred_val.clone()) {
                let mut lock = self.last_injected_cred.lock().await;
                *lock = Some(finding);
            }
        }
        Ok(vec![])
    }
}

#[tokio::test]
async fn test_lateral_movement_positive() {
    let inventory = SwarmInventory::new();
    let fired_chains = DashSet::new();
    let last_cred = Arc::new(tokio::sync::Mutex::new(None));
    let mock_nxc = Box::new(MockNetExec { last_injected_cred: last_cred.clone() }) as Box<dyn ScannerPlugin>;
    let plugins: Vec<Box<dyn ScannerPlugin>> = vec![mock_nxc];

    // Finding: NTLM Hash in Scope-A
    let mut f = Finding::new(FINDING_NTLM_HASH_CAPTURED, Category::CredentialLeak, Severity::High, "Captured Hash", serde_json::json!({"hash": "123"}));
    f.core.scope_id = "Scope-A".to_string();
    
    // Manual ingestion (Simulating Orchestrator fast-path)
    inventory.ingest_finding(f.clone(), TrustLevel::Private);

    // Target in Scope-A
    let target = TargetHost {
        host: "127.0.0.1".to_string(),
        scope_id: "Scope-A".to_string(),
        extra_data: Arc::new(serde_json::json!({})),
        ..Default::default()
    };

    let rules = reactive_engine::get_all_rules();
    
    // Evaluate
    reactive_engine::evaluate(
        &rules,
        &[f],
        &target,
        &plugins,
        &ScanLayerPolicy::preset_audit(),
        &ApprovalGate::new(50),
        &fired_chains,
        Some(&inventory)
    ).await;

    let injected = last_cred.lock().await;
    assert!(injected.is_some(), "NetExec should have been triggered with injected credential in same scope");
    assert_eq!(injected.as_ref().unwrap().core.id, FINDING_NTLM_HASH_CAPTURED);
}

#[tokio::test]
async fn test_lateral_movement_negative_scope() {
    let inventory = SwarmInventory::new();
    let fired_chains = DashSet::new();
    let last_cred = Arc::new(tokio::sync::Mutex::new(None));
    let mock_nxc = Box::new(MockNetExec { last_injected_cred: last_cred.clone() }) as Box<dyn ScannerPlugin>;
    let plugins: Vec<Box<dyn ScannerPlugin>> = vec![mock_nxc];

    // Finding in Scope-A
    let mut f = Finding::new(FINDING_NTLM_HASH_CAPTURED, Category::CredentialLeak, Severity::High, "Captured Hash", serde_json::json!({"hash": "123"}));
    f.core.scope_id = "Scope-A".to_string();
    inventory.ingest_finding(f.clone(), TrustLevel::Private);

    // Target in Scope-B (DIFFERENT SCOPE)
    let target = TargetHost {
        host: "192.168.1.1".to_string(),
        scope_id: "Scope-B".to_string(),
        extra_data: Arc::new(serde_json::json!({})),
        ..Default::default()
    };

    let rules = reactive_engine::get_all_rules();
    
    reactive_engine::evaluate(
        &rules,
        &[f],
        &target,
        &plugins,
        &ScanLayerPolicy::preset_audit(),
        &ApprovalGate::new(50),
        &fired_chains,
        Some(&inventory)
    ).await;

    let injected = last_cred.lock().await;
    assert!(injected.is_none(), "NetExec should NOT have been triggered for a different scope due to ACL");
}

#[cfg(feature = "sovereign")]
mod sovereign_tests {
    use super::*;
    use redteam_rust_core::plugins::exploitation::network::responder::ResponderScanner;
    use redteam_rust_core::core::orchestrator::c2::sliver_feedback::{C2Client, SliverFeedbackLoop};
    use redteam_rust_core::core::orchestrator::c2::sliver_proto::sliver::sliverpb::{CallExtensionReq, CallExtension};
    use std::sync::Mutex;

    // ============================================================
    // Phase 5.3: Responder Log Parser Tests
    // ============================================================

    /// PASS: Standard Responder SMB NTLMv2 log format is correctly parsed.
    #[test]
    fn test_responder_parser_standard_format() {
        let log = "[SMB] NTLMv2-SSP Client   : 192.168.1.50\n\
                   [SMB] NTLMv2-SSP Username : CORP\\jsmith\n\
                   [SMB] NTLMv2-SSP Hash     : jsmith::CORP:aad3b435b51404ee:DEADBEEF\n";

        let captures = ResponderScanner::parse_responder_log(log);

        assert_eq!(captures.len(), 1, "Should parse exactly 1 capture");
        let c = &captures[0];
        assert_eq!(c.client_ip, "192.168.1.50");
        assert_eq!(c.domain, "CORP");
        assert_eq!(c.username, "jsmith");
        assert_eq!(c.hash, "jsmith::CORP:aad3b435b51404ee:DEADBEEF");
    }

    /// PASS: Multiple sequential capture blocks are all extracted.
    #[test]
    fn test_responder_parser_multiple_captures() {
        let log = "[SMB] NTLMv2-SSP Client   : 10.0.0.1\n\
                   [SMB] NTLMv2-SSP Username : DOMAIN\\alice\n\
                   [SMB] NTLMv2-SSP Hash     : alice::DOMAIN:111:aaa\n\
                   [SMB] NTLMv2-SSP Client   : 10.0.0.2\n\
                   [SMB] NTLMv2-SSP Username : DOMAIN\\bob\n\
                   [SMB] NTLMv2-SSP Hash     : bob::DOMAIN:222:bbb\n";

        let captures = ResponderScanner::parse_responder_log(log);

        assert_eq!(captures.len(), 2, "Should parse 2 captures");
        assert_eq!(captures[0].username, "alice");
        assert_eq!(captures[0].domain, "DOMAIN");
        assert_eq!(captures[1].username, "bob");
        assert_eq!(captures[1].client_ip, "10.0.0.2");
    }

    /// PASS: Empty and malformed inputs produce zero captures without panicking.
    #[test]
    fn test_responder_parser_empty_and_malformed() {
        assert_eq!(ResponderScanner::parse_responder_log("").len(), 0);
        assert_eq!(
            ResponderScanner::parse_responder_log("[*] Some other Responder log line\n[HTTP] GET ...").len(),
            0,
            "Non-SMB-NTLMv2 lines should produce no captures"
        );
        // Incomplete block (no Hash line) should not yield a capture
        let incomplete = "[SMB] NTLMv2-SSP Client   : 10.0.0.1\n\
                          [SMB] NTLMv2-SSP Username : DOMAIN\\user\n";
        assert_eq!(
            ResponderScanner::parse_responder_log(incomplete).len(),
            0,
            "Incomplete block (no Hash line) should not be emitted"
        );
    }

    // ============================================================
    // Phase 5.5: Mimikatz Parser Tests
    // ============================================================

    /// PASS: Standard Mimikatz SAM output is correctly parsed.
    #[test]
    fn test_mimikatz_parser_standard() {
        let output = "User : Administrator\n\
                      Hash NTLM: 2b576acbe6bcfda72f2b576acbe6bcfd\n";
        
        let results = SliverFeedbackLoop::parse_mimikatz_output(output);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "Administrator");
        assert_eq!(results[0].1, "2b576acbe6bcfda72f2b576acbe6bcfd");
    }

    /// PASS: Multiple blocks in Mimikatz output are all extracted.
    #[test]
    fn test_mimikatz_parser_multi_block() {
        let output = "msv :\n\
                      [00000003] Primary\n\
                      * Username : jdoe\n\
                      * Domain   : CORP\n\
                      * User : jdoe\n\
                      * Hash NTLM: 11111111111111111111111111111111\n\
                      * User : guest\n\
                      * Hash NTLM: 00000000000000000000000000000000\n";
        
        let results = SliverFeedbackLoop::parse_mimikatz_output(output);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].0, "jdoe");
        assert_eq!(results[1].0, "guest");
        assert_eq!(results[1].1, "00000000000000000000000000000000");
    }

    // ============================================================================
    // CONTRACT TESTS — gRPC path (mock client, no live Sliver server required)
    // ============================================================================

    /// Captures every CallExtensionReq it receives for later assertion.
    #[derive(Clone)]
    struct MockC2Client {
        /// The Mimikatz output to return.
        output: String,
        /// Whether to simulate a gRPC error.
        fail: bool,
        /// Side-channel: records the session_id from the last request.
        captured_session_id: Arc<Mutex<Option<String>>>,
    }

    #[async_trait]
    impl C2Client for MockC2Client {
        async fn call_extension(&mut self, req: CallExtensionReq) -> anyhow::Result<CallExtension> {
            // Record what session_id arrived in the request for assertion.
            if let Some(inner) = &req.request {
                *self.captured_session_id.lock().unwrap() = Some(inner.session_id.clone());
            }

            if self.fail {
                return Err(anyhow::anyhow!("simulated gRPC error"));
            }

            Ok(CallExtension {
                output: self.output.as_bytes().to_vec(),
                ..Default::default()
            })
        }
    }

    /// CONTRACT-1: session_id MUST be propagated into CallExtensionReq.request.
    /// Verifies the BUG-CRITICAL fix is structurally enforced.
    #[tokio::test]
    async fn test_contract_session_id_injected() {
        let captured = Arc::new(Mutex::new(None::<String>));
        let client = MockC2Client {
            output: String::new(),
            fail: false,
            captured_session_id: captured.clone(),
        };
        let inventory = Arc::new(SwarmInventory::new());

        SliverFeedbackLoop::handle_new_session(client, "sess-DEAD-BEEF".to_string(), inventory)
            .await
            .unwrap();

        let recorded = captured.lock().unwrap().clone();
        assert_eq!(
            recorded.as_deref(),
            Some("sess-DEAD-BEEF"),
            "session_id must be injected into CommonRequest.session_id"
        );
    }

    /// CONTRACT-2: Valid Mimikatz output MUST trigger inventory.ingest_finding.
    /// Verifies the parse → ingest pipeline is wired correctly.
    #[tokio::test]
    async fn test_contract_credential_ingested_to_inventory() {
        let mimikatz_output = "\
            User : jdoe\n\
            Hash NTLM: aabbccddeeff00112233445566778899\n";

        let client = MockC2Client {
            output: mimikatz_output.to_string(),
            fail: false,
            captured_session_id: Arc::new(Mutex::new(None)),
        };
        let inventory = Arc::new(SwarmInventory::new());

        SliverFeedbackLoop::handle_new_session(
            client,
            "sess-test-ingestion".to_string(),
            inventory.clone(),
        )
        .await
        .unwrap();

        // Credentials are ingested with scope_id = "Auto-Inferred".
        // get_authorized_credentials filters by scope; we verify at least one credential
        // was ingested by checking the global store via a known scope.
        // Since scope_id = "Auto-Inferred", query that scope.
        let creds = inventory.get_authorized_credentials("Auto-Inferred");
        assert!(
            !creds.is_empty(),
            "Credential from Mimikatz output must be ingested into SwarmInventory"
        );
        let first = &creds[0];
        // Finding title matches the NTLM_HASH_CAPTURED constant (verified via Deref to CoreFinding)
        assert_eq!(first.core.id, redteam_rust_core::models::constants::FINDING_NTLM_HASH_CAPTURED);
        // JSON evidence is stored in finding.evidence.evidence.data
        let data = &first.evidence.primary.as_ref().unwrap().data;
        assert_eq!(data["ntlm"], "aabbccddeeff00112233445566778899");
        assert_eq!(data["username"], "jdoe");
    }

    /// CONTRACT-3: A gRPC error MUST propagate as Err — no panic, no silent drop.
    #[tokio::test]
    async fn test_contract_grpc_error_propagates() {
        let client = MockC2Client {
            output: String::new(),
            fail: true,
            captured_session_id: Arc::new(Mutex::new(None)),
        };
        let inventory = Arc::new(SwarmInventory::new());

        let result = SliverFeedbackLoop::handle_new_session(
            client,
            "sess-err-test".to_string(),
            inventory,
        )
        .await;

        assert!(result.is_err(), "gRPC failure must propagate as Err, not be swallowed");
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("simulated gRPC error"), "Error message must be preserved: {}", msg);
    }
}
