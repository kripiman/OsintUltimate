use crate::plugins::reporting::platform_client::PlatformClient;
use crate::core::policy::ReloadablePolicy;
use anyhow::Result;
use std::sync::Arc;
use std::path::PathBuf;
use serde_json::json;

pub struct ScopeSyncer {
    clients: Vec<(PlatformClient, String)>, // (client, program_handle)
    policy_path: PathBuf,
    policy: Arc<ReloadablePolicy>,
}

impl ScopeSyncer {
    pub fn new(policy: Arc<ReloadablePolicy>, policy_path: PathBuf) -> Self {
        Self {
            clients: Vec::new(),
            policy_path,
            policy,
        }
    }

    pub fn add_client(&mut self, client: PlatformClient, handle: String) {
        self.clients.push((client, handle));
    }

    pub async fn sync(&self) -> Result<()> {
        let mut all_scopes = std::collections::HashSet::new();

        for (client, handle) in &self.clients {
            tracing::info!("🛡️ V14.6 SCOPE: Fetching scope for {}...", handle);
            match client.fetch_in_scope(handle).await {
                Ok(scopes) => {
                    tracing::info!("🛡️ V14.6 SCOPE: Found {} assets for {}", scopes.len(), handle);
                    for s in scopes {
                        all_scopes.insert(s);
                    }
                }
                Err(e) => tracing::error!("❌ V14.6 SCOPE: Failed to fetch scope for {}: {}", handle, e),
            }
        }

        if all_scopes.is_empty() {
            tracing::warn!("🛡️ V14.6 SCOPE: No scopes fetched during sync. Skipping policy update.");
            return Ok(());
        }

        let in_scope: Vec<serde_json::Value> = all_scopes.into_iter()
            .map(|s| json!({ "target": s }))
            .collect();

        let policy_json = json!({ "in_scope": in_scope });
        
        let content = serde_json::to_string_pretty(&policy_json)?;
        
        // Ensure directory exists
        if let Some(parent) = self.policy_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        
        if let Err(e) = std::fs::write(&self.policy_path, content) {
            tracing::warn!("❌ V14.6 SCOPE: Failed to write policy file to {:?}: {}. Policy will NOT be reloaded.", self.policy_path, e);
            return Err(e.into());
        }

        tracing::info!("🛡️ V14.6 SCOPE: Synchronized {} targets to {:?}", in_scope.len(), self.policy_path);
        
        self.policy.reload();
        
        Ok(())
    }
}
