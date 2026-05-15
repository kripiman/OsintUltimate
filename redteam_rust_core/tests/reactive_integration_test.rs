use redteam_rust_core::core::reactive_engine::ReactiveEngine;
use redteam_rust_core::models::{Finding, Category, Severity, TargetHost};
use redteam_rust_core::models::constants::{PLUGIN_NETEXEC, FINDING_ATTACK_PATH};
use redteam_rust_core::core::capability_layer::ScanLayerPolicy;
use redteam_rust_core::core::approval_gate::ApprovalGate;
use dashmap::DashSet;
use redteam_rust_core::plugins::{ScannerPlugin, PluginMetadata, RiskLevel, TargetType, Capability, PluginStatus};
use redteam_rust_core::core::capability_layer::ScanLayer;
use anyhow::Result;
use async_trait::async_trait;

pub struct MockPlugin;

#[async_trait]
impl ScannerPlugin for MockPlugin {
    fn name(&self) -> &'static str { PLUGIN_NETEXEC }
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: "Mock NetExec".to_string(),
            target_type: TargetType::Windows,
            risk_level: RiskLevel::Safe,
            layer: ScanLayer::Scanning,
            capabilities: vec![Capability::VulnerabilityScanning],
            ..Default::default()
        }
    }
    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::VulnerabilityScanning]
    }
    async fn check_dependencies(&self) -> Result<bool> {
        Ok(true)
    }
    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        // Return a finding to verify depth propagation
        Ok(vec![Finding::new(
            "MOCK_VULN",
            Category::Exploitation,
            Severity::High,
            "Mock finding from chain",
            serde_json::json!({"target": target.host})
        )])
    }
    async fn poll_status(&self) -> Result<PluginStatus> {
        Ok(PluginStatus::Running)
    }
    async fn stop(&self) -> Result<()> {
        Ok(())
    }
    fn as_c2_operator(&self) -> Option<&dyn redteam_rust_core::core::orchestrator::c2::C2Operator> {
        None
    }
    fn set_feedback_channel(&self, _tx: tokio::sync::mpsc::Sender<TargetHost>) {}
}

#[tokio::test]
async fn test_attack_path_triggers_netexec_with_depth() {
    let engine = ReactiveEngine::new();
    
    // 1. Setup synthetic target and finding
    let target = TargetHost {
        host: "DC01.target.local".to_string(),
        ..Default::default()
    };
    
    let finding = Finding::new(
        &format!("{}:domain_admin", FINDING_ATTACK_PATH),
        Category::Windows,
        Severity::Critical,
        "Attack path to Domain Admin discovered",
        serde_json::json!({
            "host": "DC01.target.local",
            "path": ["USER", "GROUP", "COMPUTER"]
        })
    );
    
    // 2. Setup dependencies
    let findings = vec![finding];
    let mock_plugin = Box::new(MockPlugin);
    let plugins: Vec<Box<dyn ScannerPlugin>> = vec![mock_plugin];
    let layer_policy = ScanLayerPolicy::preset_authorized_red_team();
    let approval_gate = ApprovalGate::for_authorized_testing();
    let fired_chains = DashSet::new();
    
    // 3. Evaluate
    let result = engine.evaluate(
        &findings,
        &target,
        &plugins,
        &layer_policy,
        &approval_gate,
        &fired_chains,
        None
    ).await;
    
    // 4. Verify Depth
    assert!(!result.is_empty());
    assert_eq!(result[0].core.id, "MOCK_VULN");
    assert_eq!(result[0].core.reactive_depth, 1);
}
