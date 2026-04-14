use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

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

#[derive(Debug, Deserialize)]
pub(crate) struct CloudflareDnsResponse {
    pub success: bool,
    pub result: Option<CloudflareDnsRecord>,
    pub errors: Vec<CloudflareError>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CloudflareDnsRecord {
    pub id: String,
    pub _name: String,
    pub _type: String,
    pub _content: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CloudflareError {
    pub code: u32,
    pub message: String,
}
