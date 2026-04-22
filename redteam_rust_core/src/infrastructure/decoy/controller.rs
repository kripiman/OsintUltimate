use anyhow::{Result, Context};
use chrono::Utc;
use dashmap::DashMap;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use std::sync::Arc;
use tokio::sync::{mpsc, Semaphore};
use tracing::{info, warn, error};

use super::config::DecoyConfig;
use super::models::{DecoyRecord, TripwireEvent, CloudflareDnsResponse};
use crate::utils::proxy::ProxyManager;

pub struct DecoyController {
    pub(crate) config: DecoyConfig,
    pub(crate) proxy_manager: Arc<ProxyManager>,
    /// Active decoys indexed by FQDN
    pub(crate) active_decoys: DashMap<String, DecoyRecord>,
    /// Tripwire events buffer — batched writes to SQLite
    pub(crate) tripwire_tx: mpsc::Sender<TripwireEvent>,
    /// Listener connection limiter (backpressure)
    pub(crate) connection_semaphore: Arc<Semaphore>,
}

impl DecoyController {
    /// Creates a new DecoyController. The `tripwire_rx` should be consumed
    /// by a background task that persists events to SQLite.
    pub fn new(config: DecoyConfig, pm: Arc<crate::utils::proxy::ProxyManager>) -> Result<(Self, mpsc::Receiver<TripwireEvent>)> {
        config.validate()?;
        let max_connections = config.max_listener_connections.clamp(1, 50);
        let (tx, rx) = mpsc::channel(32); // 32-slot buffer for backpressure

        Ok((
            Self {
                config,
                proxy_manager: pm,
                active_decoys: DashMap::new(),
                tripwire_tx: tx,
                connection_semaphore: Arc::new(Semaphore::new(max_connections)),
            },
            rx,
        ))
    }

    fn get_client(&self) -> Result<reqwest::Client> {
        let (_, client) = self.proxy_manager.get_client_fail_closed("api.cloudflare.com")?;
        Ok(client)
    }

    fn cf_headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", self.config.cloudflare_api_token))
                .expect("Invalid Cloudflare API token format"),
        );
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers
    }

    // ─────────────────────────────────────────────────────────────────────
    // DEPLOY CANARIES
    // ─────────────────────────────────────────────────────────────────────

    /// Deploys all canary subdomains as A records in Cloudflare,
    /// pointing to the configured callback IP.
    pub async fn deploy_canaries(&self) -> Result<Vec<DecoyRecord>> {
        info!(
            "🍯 DECOY: Deploying {} canary subdomains on {}",
            self.config.canary_subdomains.len(),
            self.config.domain
        );

        let mut deployed = Vec::new();

        for subdomain in &self.config.canary_subdomains {
            let fqdn = format!("{}.{}", subdomain, self.config.domain);

            match self.create_dns_record(&fqdn).await {
                Ok(record_id) => {
                    let record = DecoyRecord {
                        fqdn: fqdn.clone(),
                        dns_record_id: record_id,
                        deployed_at: Utc::now(),
                        active: true,
                    };
                    self.active_decoys.insert(fqdn.clone(), record.clone());
                    deployed.push(record);
                    info!("🍯 DECOY: Canary deployed → {}", fqdn);
                }
                Err(e) => {
                    warn!("🍯 DECOY: Failed to deploy canary '{}': {}", fqdn, e);
                }
            }
        }

        info!("🍯 DECOY: {}/{} canaries active", deployed.len(), self.config.canary_subdomains.len());
        Ok(deployed)
    }

    /// Creates a single DNS A record via Cloudflare API.
    async fn create_dns_record(&self, fqdn: &str) -> Result<String> {
        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records",
            self.config.cloudflare_zone_id
        );

        let body = serde_json::json!({
            "type": "A",
            "name": fqdn,
            "content": self.config.callback_ip,
            "ttl": 120,      // 2-minute TTL — short for quick teardown
            "proxied": false  // Direct A record, no CF proxy (we want raw connections)
        });

        let response: CloudflareDnsResponse = self.get_client()?
            .post(&url)
            .headers(self.cf_headers())
            .json(&body)
            .send()
            .await
            .context("Cloudflare API request failed")?
            .json()
            .await
            .context("Failed to parse Cloudflare response")?;

        if response.success {
            if let Some(record) = response.result {
                Ok(record.id)
            } else {
                anyhow::bail!("Cloudflare returned success but no record data for {}", fqdn)
            }
        } else {
            let errors: Vec<String> = response.errors.iter().map(|e| format!("[{}] {}", e.code, e.message)).collect();
            anyhow::bail!("Cloudflare DNS creation failed for {}: {}", fqdn, errors.join(", "))
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // DESTROY CANARIES (Cleanup)
    // ─────────────────────────────────────────────────────────────────────

    /// Tears down all active canary DNS records. Call on shutdown.
    pub async fn destroy_canaries(&self) -> Result<()> {
        info!("🍯 DECOY: Tearing down all canary records...");

        let records: Vec<(String, DecoyRecord)> = self.active_decoys.iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect();

        for (fqdn, record) in records {
            if let Err(e) = self.delete_dns_record(&record.dns_record_id).await {
                error!("🍯 DECOY: Failed to delete DNS record for {}: {}", fqdn, e);
            } else {
                self.active_decoys.remove(&fqdn);
                info!("🍯 DECOY: Canary removed ← {}", fqdn);
            }
        }

        Ok(())
    }

    /// Deletes a single DNS record via Cloudflare API.
    async fn delete_dns_record(&self, record_id: &str) -> Result<()> {
        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records/{}",
            self.config.cloudflare_zone_id, record_id
        );

        let res = self.get_client()?
            .delete(&url)
            .headers(self.cf_headers())
            .send()
            .await
            .context("Cloudflare delete request failed")?;

        if res.status().is_success() {
            Ok(())
        } else {
            anyhow::bail!("Cloudflare DNS delete returned HTTP {}", res.status())
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // TRIPWIRE PROCESSING
    // ─────────────────────────────────────────────────────────────────────

    /// Records a tripwire event. Called by the HTTP listener when a canary is hit.
    /// Uses backpressure: if the channel is full, the event is dropped with a warning.
    pub async fn record_tripwire(&self, event: TripwireEvent) {
        match self.tripwire_tx.try_send(event.clone()) {
            Ok(()) => {
                warn!(
                    "🚨 TRIPWIRE FIRED: {} probed by {} via {} {}",
                    event.fqdn, event.source_ip, event.method, event.path
                );
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                warn!("🚨 TRIPWIRE: Event buffer full (backpressure). Event for {} dropped.", event.fqdn);
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                error!("🚨 TRIPWIRE: Persistence channel closed. Events are being lost!");
            }
        }
    }

    /// Converts a tripwire event into a `Finding` for the scan pipeline.
    pub fn tripwire_to_finding(event: &TripwireEvent) -> crate::models::Finding {
        crate::models::Finding::new(
            &format!("TRIPWIRE-{}", event.fqdn.replace('.', "-")),
            crate::models::Category::Recon,
            crate::models::Severity::Critical,
            &format!(
                "Infrastructure probe detected: {} was accessed by {} ({} {})",
                event.fqdn, event.source_ip, event.method, event.path
            ),
            serde_json::json!({
                "fqdn": event.fqdn,
                "source_ip": event.source_ip,
                "method": event.method,
                "path": event.path,
                "user_agent": event.user_agent,
                "headers": event.headers_json,
                "timestamp": event.triggered_at.to_rfc3339(),
                "ja3_hash": event.ja3_hash,
            }),
        )
    }

    /// Returns a reference to the connection semaphore for listener backpressure.
    pub fn connection_semaphore(&self) -> Arc<Semaphore> {
        Arc::clone(&self.connection_semaphore)
    }

    /// Returns the count of currently active decoys.
    pub fn active_count(&self) -> usize {
        self.active_decoys.len()
    }

    /// Lists all active decoy FQDNs.
    pub fn list_active(&self) -> Vec<String> {
        self.active_decoys.iter().map(|e| e.key().clone()).collect()
    }

    /// Check if a given FQDN is one of our canaries (used by the listener to validate).
    pub fn is_our_canary(&self, fqdn: &str) -> bool {
        self.active_decoys.contains_key(fqdn)
    }
}
