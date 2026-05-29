/// HTTPS Domain Fronting over HTTP/3.
///
/// Separates QUIC SNI from HTTP :authority to bypass CDN-based filtering.
/// The QUIC handshake presents `front_domain` in SNI (TLS ClientHello),
/// while the HTTP/3 request targets `target_domain` in the Host pseudo-header.
///
/// # Example
/// ```rust,ignore
/// let client = DomainFrontClient::new("allowed-domain.com", "real-target.com").await?;
/// let resp = client.get("/api/data").await?;
/// ```
use anyhow::Result;
use bytes::{Buf, Bytes};

use crate::core::net_evasion::http3_client::Http3Response;
use crate::core::net_evasion::quinn_client::QuinnEvasionClient;

/// Domain fronting client.
pub struct DomainFrontClient {
    quinn_client: QuinnEvasionClient,
    front_domain: String,
    target_domain: String,
}

impl DomainFrontClient {
    /// Create a new domain fronting client.
    ///
    /// `front_domain` is used for DNS resolution and QUIC SNI.
    /// `target_domain` is used in the HTTP :authority pseudo-header.
    pub fn new(front_domain: &str, target_domain: &str) -> Result<Self> {
        let quinn_client = QuinnEvasionClient::new()?;
        Ok(Self {
            quinn_client,
            front_domain: front_domain.to_string(),
            target_domain: target_domain.to_string(),
        })
    }

    /// Perform a domain-fronted HTTP/3 GET.
    pub async fn get(&self, path: &str) -> Result<Http3Response> {
        self.request(http::Method::GET, path, http::HeaderMap::new(), None)
            .await
    }

    /// Perform a domain-fronted HTTP/3 POST.
    pub async fn post(&self, path: &str, body: Bytes) -> Result<Http3Response> {
        self.request(http::Method::POST, path, http::HeaderMap::new(), Some(body))
            .await
    }

    /// Raw domain-fronted HTTP/3 request.
    async fn request(
        &self,
        method: http::Method,
        path: &str,
        headers: http::HeaderMap,
        body: Option<Bytes>,
    ) -> Result<Http3Response> {
        // 1. DNS-resolve front_domain to get CDN edge IP
        let lookup = format!("{}:443", self.front_domain);
        let mut addrs = tokio::net::lookup_host(&lookup).await?;
        let addr = addrs
            .next()
            .ok_or_else(|| anyhow::anyhow!("DNS lookup returned no addresses for {}", self.front_domain))?;

        // 2. QUIC connect with front_domain as SNI
        let quinn_conn = self.quinn_client.connect(addr, &self.front_domain).await?;

        // 3. Wrap in h3-quinn connection
        let h3_quinn_conn = h3_quinn::Connection::new(quinn_conn.into_connection());

        // 4. Build h3 client
        let (mut h3_driver, mut send_request) = h3::client::new(h3_quinn_conn).await?;

        // 5. Spawn driver task (Path A: per-request spawn)
        let _driver = tokio::spawn(async move {
            let _ = h3_driver.wait_idle().await;
        });

        // 6. Build HTTP request with target_domain as :authority
        let full_uri = format!("https://{}:443{}", self.target_domain, path);
        let mut request = http::Request::builder()
            .method(method)
            .uri(&full_uri)
            .version(http::Version::HTTP_3)
            .body(())?;
        *request.headers_mut() = headers;

        // 7. Send request
        let mut req_stream = send_request.send_request(request).await?;

        // 8. Send body if present
        if let Some(data) = body {
            req_stream.send_data(data).await?;
        }
        req_stream.finish().await?;

        // 9. Receive response
        let response = req_stream.recv_response().await?;
        let status = response.status().as_u16();
        let resp_headers = response.headers().clone();

        // 10. Collect response body
        let mut body_buf = bytes::BytesMut::new();
        let timeout = std::time::Duration::from_secs(30);
        let recv_body = async {
            while let Some(chunk) = req_stream.recv_data().await? {
                body_buf.extend_from_slice(chunk.chunk());
            }
            Ok::<_, h3::Error>(())
        };
        match tokio::time::timeout(timeout, recv_body).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(anyhow::anyhow!("h3 body recv error: {}", e)),
            Err(_) => return Err(anyhow::anyhow!("h3 body recv timeout")),
        }

        Ok(Http3Response {
            status,
            headers: resp_headers,
            body: body_buf.freeze(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_domain_front_client_new() {
        let client = DomainFrontClient::new("cloudflare.com", "real-target.com");
        assert!(client.is_ok(), "DomainFrontClient::new() should succeed");
    }
}
