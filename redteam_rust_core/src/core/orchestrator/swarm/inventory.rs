use crate::models::{Finding, TargetHost, Category, Severity};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TrustLevel {
    /// Only accessible within the same scope_id.
    Private,
    /// Shared with a specific list of scope_ids.
    TrustGroup(Vec<String>),
    /// Shared with all scopes.
    Global,
}

#[derive(Debug, Clone)]
pub struct InventoryItem<T> {
    pub data: T,
    pub owner_scope_id: String,
    pub trust_level: TrustLevel,
}

/// A sovereign-grade inventory for cross-target intelligence sharing within the Swarm.
/// Implements ACL-based isolation to prevent credential bleeding between unrelated scopes.
pub struct SwarmInventory {
    pub credentials: DashMap<String, InventoryItem<Finding>>,
    pub high_value_targets: DashMap<String, InventoryItem<TargetHost>>,
}

impl SwarmInventory {
    pub fn new() -> Self {
        Self {
            credentials: DashMap::new(),
            high_value_targets: DashMap::new(),
        }
    }

    /// Adds a finding to the inventory if it's a high-severity credential.
    pub fn ingest_finding(&self, finding: Finding, trust_level: TrustLevel) {
        if finding.category == Category::CredentialLeak && finding.severity >= Severity::High {
            let key = format!("{}:{}", finding.core.scope_id, finding.core.id);
            self.credentials.insert(key, InventoryItem {
                owner_scope_id: finding.core.scope_id.clone(),
                data: finding,
                trust_level,
            });
        }
    }

    /// Returns all credentials authorized for the given scope_id.
    pub fn get_authorized_credentials(&self, target_scope_id: &str) -> Vec<Finding> {
        self.credentials.iter()
            .filter(|entry| {
                let item = entry.value();
                match &item.trust_level {
                    TrustLevel::Private => item.owner_scope_id == target_scope_id,
                    TrustLevel::TrustGroup(group) => group.contains(&target_scope_id.to_string()) || item.owner_scope_id == target_scope_id,
                    TrustLevel::Global => true,
                }
            })
            .map(|entry| entry.value().data.clone())
            .collect()
    }
}

impl Default for SwarmInventory {
    fn default() -> Self {
        Self::new()
    }
}
