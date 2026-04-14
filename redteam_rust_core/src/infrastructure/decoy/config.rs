use anyhow::Result;
use serde::{Deserialize, Serialize};

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
