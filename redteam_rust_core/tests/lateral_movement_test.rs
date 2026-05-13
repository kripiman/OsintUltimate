use async_trait::async_trait;
use redteam_rust_core::plugins::{ScannerPlugin, PluginMetadata, Capability};
use redteam_rust_core::models::{TargetHost, Finding, Severity, Category};
use redteam_rust_core::models::constants::*;
use redteam_rust_core::core::swarm::inventory::{SwarmInventory, TrustLevel};
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
    let mut target = TargetHost::default();
    target.host = "127.0.0.1".to_string();
    target.scope_id = "Scope-A".to_string();
    target.extra_data = Arc::new(serde_json::json!({}));

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
    let mut target = TargetHost::default();
    target.host = "192.168.1.1".to_string();
    target.scope_id = "Scope-B".to_string();
    target.extra_data = Arc::new(serde_json::json!({}));

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

// ============================================================
// Phase 5.3: Responder Log Parser Tests
// ============================================================
use redteam_rust_core::plugins::exploitation::network::responder::ResponderScanner;

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
