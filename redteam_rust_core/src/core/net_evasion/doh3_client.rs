/// DNS-over-HTTP/3 (DoH3) client.
///
/// Performs DNS resolution and raw DNS queries over HTTP/3 (RFC 8484 + RFC 9230).
/// Useful for bypassing port-53 filtering and for DNS-based data exfiltration.
///
/// # Limitation
/// The underlying HTTP/3 client resolves the URL host via `SocketAddr::parse()`,
/// which does **not** perform DNS lookups. Therefore resolver URLs must use
/// **IP addresses** (e.g. `https://1.1.1.1/dns-query`), not hostnames.
use anyhow::Result;
use bytes::Bytes;
use std::net::IpAddr;
use std::str::FromStr;

use crate::core::net_evasion::http3_client::Http3EvasionClient;

/// Default Cloudflare DoH3 endpoint (IP-based).
const DEFAULT_DOH3_URL: &str = "https://1.1.1.1/dns-query";

/// DoH3 client wrapping an `Http3EvasionClient`.
pub struct DoH3Client {
    inner: Http3EvasionClient,
    resolver_url: String,
}

impl DoH3Client {
    /// Create a DoH3 client with the default Cloudflare resolver.
    pub fn new() -> Result<Self> {
        let inner = Http3EvasionClient::new()?;
        Ok(Self {
            inner,
            resolver_url: DEFAULT_DOH3_URL.to_string(),
        })
    }

    /// Create a DoH3 client with a custom resolver URL.
    ///
    /// # Limitation
    /// The URL must use an IP address (not a hostname) for the host component,
    /// because the underlying QUIC connection does not perform DNS resolution.
    pub fn with_resolver(url: &str) -> Result<Self> {
        let inner = Http3EvasionClient::new()?;
        Ok(Self {
            inner,
            resolver_url: url.to_string(),
        })
    }

    /// Resolve a hostname via DoH3. Returns IPv4 and IPv6 addresses.
    pub async fn resolve(&self, name: &str) -> Result<Vec<IpAddr>> {
        use hickory_resolver::proto::op::{Message, Query};
        use hickory_resolver::proto::rr::{Name, RecordType};

        let mut msg = Message::new();
        let query = Query::query(
            Name::from_str(name)?,
            RecordType::A,
        );
        msg.add_query(query);
        let wire = msg.to_vec()?;

        let b64 = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            &wire,
        );

        let url = format!("{}?dns={}", self.resolver_url, b64);
        let resp = self.inner.get(&url).await?;
        Self::parse_dns_response(&resp.body)
    }

    /// Send a raw DNS wire-format query and return the raw response bytes.
    ///
    /// The `dns_payload` should be a complete DNS message (e.g. built with
    /// `hickory_proto::op::Message`).
    pub async fn raw_query(&self, dns_payload: &[u8]) -> Result<Vec<u8>> {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "content-type",
            "application/dns-message".parse()?,
        );
        headers.insert(
            "accept",
            "application/dns-message".parse()?,
        );

        let resp = self
            .inner
            .request(
                http::Method::POST,
                &self.resolver_url,
                headers,
                Some(Bytes::copy_from_slice(dns_payload)),
            )
            .await?;

        Ok(resp.body.to_vec())
    }

    /// Parse a DNS response body into IP addresses.
    fn parse_dns_response(body: &[u8]) -> Result<Vec<IpAddr>> {
        use hickory_resolver::proto::op::Message;
        use hickory_resolver::proto::rr::RecordType;

        let msg = Message::from_vec(body)?;
        let mut addrs = Vec::new();
        for record in msg.answers() {
            match record.record_type() {
                RecordType::A => {
                    if let Some(data) = record.data() {
                        if let Some(a) = data.as_a() {
                            addrs.push(IpAddr::V4(a.0));
                        }
                    }
                }
                RecordType::AAAA => {
                    if let Some(data) = record.data() {
                        if let Some(aaaa) = data.as_aaaa() {
                            addrs.push(IpAddr::V6(aaaa.0));
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(addrs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_doh3_client_new() {
        let client = DoH3Client::new();
        assert!(client.is_ok(), "DoH3Client::new() should succeed");
    }

    #[tokio::test]
    async fn test_doh3_client_with_resolver() {
        let client = DoH3Client::with_resolver("https://8.8.8.8/dns-query");
        assert!(
            client.is_ok(),
            "DoH3Client::with_resolver() should succeed"
        );
    }

    #[test]
    fn test_parse_dns_response_empty() {
        use hickory_resolver::proto::op::Message;
        let msg = Message::new();
        let wire = msg.to_vec().unwrap();
        let addrs = DoH3Client::parse_dns_response(&wire).unwrap();
        assert!(addrs.is_empty());
    }
}
