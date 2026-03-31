use anyhow::{Result, Context};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::{mpsc, Semaphore};
use tracing::{info, warn, error};

// ─────────────────────────────────────────────────────────────────────────────
// DECOY CONFIGURATION
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecoyConfig {
    /// Base domain from Namecheap/Name.com Student Pack (e.g., "myproject.me")
    pub domain: String,
    /// Canary subdomain prefixes (e.g., ["admin-panel", "vpn-portal", "staging-api"])
    pub canary_subdomains: Vec<String>,
    /// Cloudflare Zone ID for the domain
    pub cloudflare_zone_id: String,
    /// Cloudflare API Token with DNS edit permissions
    pub cloudflare_api_token: String,
    /// IP address the canary A records should point to (ephemeral DO node)
    pub callback_ip: String,
    /// Maximum concurrent connections the listener accepts (backpressure)
    pub max_listener_connections: usize,
}

impl DecoyConfig {
    pub fn validate(&self) -> Result<()> {
        if self.domain.is_empty() {
            anyhow::bail!("DecoyConfig: domain cannot be empty");
        }
        if self.canary_subdomains.is_empty() {
            anyhow::bail!("DecoyConfig: at least one canary subdomain is required");
        }
        if self.cloudflare_zone_id.is_empty() || self.cloudflare_api_token.is_empty() {
            anyhow::bail!("DecoyConfig: Cloudflare credentials are required");
        }
        // Validate domain format — basic check
        if !self.domain.contains('.') {
            anyhow::bail!("DecoyConfig: invalid domain format '{}'", self.domain);
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DECOY & TRIPWIRE RECORDS
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecoyRecord {
    /// Full subdomain (e.g., "admin-panel.myproject.me")
    pub fqdn: String,
    /// Cloudflare DNS Record ID (for teardown)
    pub dns_record_id: String,
    /// When the decoy was deployed
    pub deployed_at: DateTime<Utc>,
    /// Whether this decoy is currently active
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TripwireEvent {
    /// Which canary was triggered
    pub fqdn: String,
    /// Source IP of the probe
    pub source_ip: String,
    /// HTTP method used (GET, HEAD, OPTIONS, etc.)
    pub method: String,
    /// Full URI path requested
    pub path: String,
    /// User-Agent header from the probing request
    pub user_agent: Option<String>,
    /// All request headers (serialized for forensic analysis)
    pub headers_json: String,
    /// Timestamp of the event
    pub triggered_at: DateTime<Utc>,
    /// Optional: JA3 TLS fingerprint hash if available
    pub ja3_hash: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// CLOUDFLARE DNS API RESPONSE MODELS
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct CloudflareDnsResponse {
    success: bool,
    result: Option<CloudflareDnsRecord>,
    errors: Vec<CloudflareError>,
}

#[derive(Debug, Deserialize)]
struct CloudflareDnsRecord {
    id: String,
    name: String,
    r#type: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct CloudflareError {
    code: u32,
    message: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// DECOY CONTROLLER
// ─────────────────────────────────────────────────────────────────────────────

pub struct DecoyController {
    config: DecoyConfig,
    client: reqwest::Client,
    /// Active decoys indexed by FQDN
    active_decoys: DashMap<String, DecoyRecord>,
    /// Tripwire events buffer — batched writes to SQLite
    tripwire_tx: mpsc::Sender<TripwireEvent>,
    /// Listener connection limiter (backpressure)
    connection_semaphore: Arc<Semaphore>,
}

impl DecoyController {
    /// Creates a new DecoyController. The `tripwire_rx` should be consumed
    /// by a background task that persists events to SQLite.
    pub fn new(config: DecoyConfig) -> Result<(Self, mpsc::Receiver<TripwireEvent>)> {
        config.validate()?;
        let max_connections = config.max_listener_connections.max(1).min(50);
        let (tx, rx) = mpsc::channel(32); // 32-slot buffer for backpressure

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .context("Failed to build Cloudflare HTTP client")?;

        Ok((
            Self {
                config,
                client,
                active_decoys: DashMap::new(),
                tripwire_tx: tx,
                connection_semaphore: Arc::new(Semaphore::new(max_connections)),
            },
            rx,
        ))
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

        let response: CloudflareDnsResponse = self.client
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

        let res = self.client
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

// ─────────────────────────────────────────────────────────────────────────────
// TRIPWIRE PERSISTENCE (Background Task)
// ─────────────────────────────────────────────────────────────────────────────

/// Spawns a background task that drains TripwireEvents from the channel
/// and persists them into SQLite (WAL mode). This decouples the listener
/// from database I/O for backpressure.
pub async fn spawn_tripwire_persister(
    mut rx: mpsc::Receiver<TripwireEvent>,
    db_url: &str,
) -> Result<tokio::task::JoinHandle<()>> {
    let pool = sqlx::SqlitePool::connect(db_url).await
        .context("Failed to connect to tripwire SQLite database")?;

    // Ensure WAL mode + create table
    sqlx::query("PRAGMA journal_mode=WAL")
        .execute(&pool).await?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS tripwire_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fqdn TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            method TEXT NOT NULL,
            path TEXT NOT NULL,
            user_agent TEXT,
            headers_json TEXT,
            ja3_hash TEXT,
            triggered_at TEXT NOT NULL
        )"
    ).execute(&pool).await?;

    let handle = tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            if let Err(e) = sqlx::query(
                "INSERT INTO tripwire_events (fqdn, source_ip, method, path, user_agent, headers_json, ja3_hash, triggered_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
            )
                .bind(&event.fqdn)
                .bind(&event.source_ip)
                .bind(&event.method)
                .bind(&event.path)
                .bind(&event.user_agent)
                .bind(&event.headers_json)
                .bind(&event.ja3_hash)
                .bind(event.triggered_at.to_rfc3339())
                .execute(&pool)
                .await
            {
                error!("🚨 TRIPWIRE: Failed to persist event: {}", e);
            }
        }
        info!("🍯 DECOY: Tripwire persister shutting down.");
    });

    Ok(handle)
}

// ─────────────────────────────────────────────────────────────────────────────
// TESTS
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decoy_config_validation_empty_domain() {
        let config = DecoyConfig {
            domain: String::new(),
            canary_subdomains: vec!["test".to_string()],
            cloudflare_zone_id: "zone123".to_string(),
            cloudflare_api_token: "token123".to_string(),
            callback_ip: "1.2.3.4".to_string(),
            max_listener_connections: 10,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_decoy_config_validation_no_subdomains() {
        let config = DecoyConfig {
            domain: "example.me".to_string(),
            canary_subdomains: vec![],
            cloudflare_zone_id: "zone123".to_string(),
            cloudflare_api_token: "token123".to_string(),
            callback_ip: "1.2.3.4".to_string(),
            max_listener_connections: 10,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_decoy_config_validation_valid() {
        let config = DecoyConfig {
            domain: "example.me".to_string(),
            canary_subdomains: vec!["admin-panel".to_string(), "vpn-portal".to_string()],
            cloudflare_zone_id: "zone123".to_string(),
            cloudflare_api_token: "token123".to_string(),
            callback_ip: "1.2.3.4".to_string(),
            max_listener_connections: 10,
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_decoy_config_validation_invalid_domain() {
        let config = DecoyConfig {
            domain: "nodotdomain".to_string(),
            canary_subdomains: vec!["test".to_string()],
            cloudflare_zone_id: "zone123".to_string(),
            cloudflare_api_token: "token123".to_string(),
            callback_ip: "1.2.3.4".to_string(),
            max_listener_connections: 10,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_tripwire_event_serialization() {
        let event = TripwireEvent {
            fqdn: "admin.example.me".to_string(),
            source_ip: "203.0.113.42".to_string(),
            method: "GET".to_string(),
            path: "/".to_string(),
            user_agent: Some("Mozilla/5.0".to_string()),
            headers_json: r#"{"Host":"admin.example.me"}"#.to_string(),
            triggered_at: Utc::now(),
            ja3_hash: Some("abc123def456".to_string()),
        };

        let json = serde_json::to_string(&event).unwrap();
        let deserialized: TripwireEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.fqdn, "admin.example.me");
        assert_eq!(deserialized.source_ip, "203.0.113.42");
    }

    #[test]
    fn test_tripwire_to_finding() {
        let event = TripwireEvent {
            fqdn: "vpn.example.me".to_string(),
            source_ip: "198.51.100.1".to_string(),
            method: "HEAD".to_string(),
            path: "/login".to_string(),
            user_agent: None,
            headers_json: "{}".to_string(),
            triggered_at: Utc::now(),
            ja3_hash: None,
        };

        let finding = DecoyController::tripwire_to_finding(&event);
        assert_eq!(finding.category, crate::models::Category::Recon);
        assert_eq!(finding.severity, crate::models::Severity::Critical);
        assert!(finding.description.contains("vpn.example.me"));
        assert!(finding.description.contains("198.51.100.1"));
    }

    #[test]
    fn test_controller_creation() {
        let config = DecoyConfig {
            domain: "example.me".to_string(),
            canary_subdomains: vec!["admin".to_string()],
            cloudflare_zone_id: "zone123".to_string(),
            cloudflare_api_token: "token123".to_string(),
            callback_ip: "1.2.3.4".to_string(),
            max_listener_connections: 10,
        };

        let (controller, _rx) = DecoyController::new(config).unwrap();
        assert_eq!(controller.active_count(), 0);
        assert!(controller.list_active().is_empty());
    }
}
