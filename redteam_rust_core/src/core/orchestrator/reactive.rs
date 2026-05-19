use std::sync::Arc;
use tracing::info;
use dashmap::DashSet;
use crate::models::{TargetHost, Finding};
use crate::models::constants::{FINDING_SSRF, PLUGIN_CLOUD_METADATA};
use crate::plugins::ScannerPlugin;
use crate::core::capability_layer::ScanLayerPolicy;
use crate::core::approval_gate::ApprovalGate;
use crate::core::orchestrator::swarm::inventory::SwarmInventory;

pub async fn run_reactive_logic(
    target: &TargetHost,
    all_findings: &[Finding],
    plugins: &Arc<Vec<Box<dyn ScannerPlugin>>>,
    layer_policy: &ScanLayerPolicy,
    approval_gate: &Arc<ApprovalGate>,
    inventory: &Arc<SwarmInventory>,
) -> Vec<Finding> {
    let fired_chains: DashSet<String> = DashSet::new();
    let rules = crate::core::reactive_engine::get_all_rules();
    
    let ctx = crate::core::reactive_engine::ReactiveContext {
        findings: all_findings,
        target,
        plugins,
        layer_policy,
        approval_gate,
        fired_chains: &fired_chains,
        inventory: Some(inventory),
    };

    let mut extra_findings = crate::core::reactive_engine::evaluate(
        &rules,
        ctx,
    ).await;

    // SSRF -> Cloud Metadata Trigger
    let ssrf_hit = all_findings.iter().find(|f| f.core.id == FINDING_SSRF).cloned();
    if let Some(ssrf_f) = ssrf_hit {
        if fired_chains.insert(format!("{}::{}", ssrf_f.core.id, PLUGIN_CLOUD_METADATA)) {
            if let Some(cloud_meta) = plugins.iter().find(|p| p.name() == PLUGIN_CLOUD_METADATA) {
                if !layer_policy.needs_approval(cloud_meta.metadata().layer) || approval_gate.is_approved(cloud_meta.name()).await {
                    info!("🔱 V15 SOVEREIGN: SSRF detected! Triggering reactive Cloud Metadata extraction for {}", target.host);
                    
                    let tool_name = ssrf_f.evidence.primary.as_ref()
                        .and_then(|e| e.data.get("tool"))
                        .and_then(|t| t.as_str());

                    let vuln_url = if tool_name == Some("ssrfmap") {
                         ssrf_f.evidence.primary.as_ref()
                            .and_then(|e| e.data.get("url"))
                            .and_then(|u| u.as_str())
                            .map(|s| s.to_string())
                    } else {
                        Some(target.host.clone())
                    };

                    if let Some(url) = vuln_url {
                        let mut reactive_snapshot = target.clone();
                        Arc::make_mut(&mut reactive_snapshot.extra_data)
                            .as_object_mut()
                            .and_then(|obj| obj.insert("ssrf_url".into(), serde_json::json!(url)));

                        if let Ok(mut cloud_findings) = cloud_meta.scan(&reactive_snapshot).await {
                            extra_findings.append(&mut cloud_findings);
                        }
                    }
                }
            }
        }
    }

    extra_findings
}
