use redteam_rust_core::models::{Finding, Category, Severity};
use redteam_rust_core::core::swarm::inventory::{SwarmInventory, TrustLevel};

#[test]
fn test_swarm_acl_isolation() {
    let inventory = SwarmInventory::new();

    // Finding 1: Credential in Scope A
    let mut f1 = Finding::new("PWD-1", Category::CredentialLeak, Severity::High, "Pass1", serde_json::json!({}));
    f1.core.scope_id = "Scope-A".to_string();

    // Finding 2: Credential in Scope B
    let mut f2 = Finding::new("PWD-2", Category::CredentialLeak, Severity::High, "Pass2", serde_json::json!({}));
    f2.core.scope_id = "Scope-B".to_string();

    // Ingest both
    inventory.ingest_finding(f1, TrustLevel::Private);
    inventory.ingest_finding(f2, TrustLevel::Private);

    // Verify Scope A only sees its own
    let creds_a = inventory.get_authorized_credentials("Scope-A");
    assert_eq!(creds_a.len(), 1);
    assert_eq!(creds_a[0].core.id, "PWD-1");

    // Verify Scope B only sees its own
    let creds_b = inventory.get_authorized_credentials("Scope-B");
    assert_eq!(creds_b.len(), 1);
    assert_eq!(creds_b[0].core.id, "PWD-2");
}

#[test]
fn test_swarm_acl_global_and_group() {
    let inventory = SwarmInventory::new();

    // Global Credential
    let mut f_global = Finding::new("GLOBAL-1", Category::CredentialLeak, Severity::High, "Pass", serde_json::json!({}));
    f_global.core.scope_id = "Admin".to_string();
    inventory.ingest_finding(f_global, TrustLevel::Global);

    // Group Credential (shared between A and C)
    let mut f_group = Finding::new("GROUP-1", Category::CredentialLeak, Severity::High, "Pass", serde_json::json!({}));
    f_group.core.scope_id = "Scope-A".to_string();
    inventory.ingest_finding(f_group, TrustLevel::TrustGroup(vec!["Scope-C".to_string()]));

    // Scope B sees only Global
    let creds_b = inventory.get_authorized_credentials("Scope-B");
    assert_eq!(creds_b.len(), 1);
    assert_eq!(creds_b[0].core.id, "GLOBAL-1");

    // Scope C sees Global and Group
    let creds_c = inventory.get_authorized_credentials("Scope-C");
    assert_eq!(creds_c.len(), 2);
}
