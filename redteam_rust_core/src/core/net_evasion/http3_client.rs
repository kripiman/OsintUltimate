/// HTTP/3 evasion client using `h3` + `h3-quinn`.
///
/// Performs HTTP/3 requests over a QUIC connection with TLS 1.3.
/// Single connection per request (connection pooling deferred to Sprint 6).
use anyhow::Result;
use bytes::{Buf, Bytes};

use crate::core::net_evasion::quinn_client::{QuinnConnection, QuinnEvasionClient};

/// HTTP/3 response wrapper.
pub struct Http3Response {
    pub status: u16,
    pub headers: http::HeaderMap,
    pub body: Bytes,
}

/// HTTP/3 evasion client.
pub struct Http3EvasionClient {
    quinn_client: QuinnEvasionClient,
}

impl Http3EvasionClient {
    /// Create a new HTTP/3 client with default TLS settings.
    pub fn new() -> Result<Self> {
        let quinn_client = QuinnEvasionClient::new()?;
        Ok(Self { quinn_client })
    }

    /// Create an HTTP/3 client from an existing `QuinnEvasionClient`.
    pub fn from_quinn(quinn_client: QuinnEvasionClient) -> Self {
        Self { quinn_client }
    }

    /// Perform an HTTP/3 GET request.
    pub async fn get(&self, url: &str) -> Result<Http3Response> {
        self.request(http::Method::GET, url, http::HeaderMap::new(), None)
            .await
    }

    /// Perform an HTTP/3 POST request.
    /// Body is sent via `send_data()` then `finish()` on the request stream.
    pub async fn post(&self, url: &str, body: Bytes) -> Result<Http3Response> {
        self.request(http::Method::POST, url, http::HeaderMap::new(), Some(body))
            .await
    }

    /// Perform an HTTP/3 request with custom method, headers, and optional body.
    ///
    /// h3 0.0.4 does not support body-in-request; the body (if any) is streamed
    /// via `RequestStream::send_data()` after `send_request()`.
    pub async fn request(
        &self,
        method: http::Method,
        url: &str,
        headers: http::HeaderMap,
        body: Option<Bytes>,
    ) -> Result<Http3Response> {
        let parsed = url::Url::parse(url)?;
        let host = parsed.host_str().unwrap_or("localhost");
        let port = parsed.port().unwrap_or(443);
        let path = parsed.path();

        let addr = format!("{}:{}", host, port).parse()?;

        // 1. QUIC connect
        let quinn_conn: QuinnConnection = self.quinn_client.connect(addr, host).await?;

        // 2. Wrap in h3-quinn connection
        let h3_quinn_conn = h3_quinn::Connection::new(quinn_conn.into_connection());

        // 3. Build h3 client
        let (mut h3_driver, mut send_request) = h3::client::new(h3_quinn_conn).await?;

        // 4. Spawn driver task locally (Path A: per-request spawn).
        // quinn::Connection drop → wait_idle() returns → task exits automatically.
        let _driver = tokio::spawn(async move {
            let _ = h3_driver.wait_idle().await;
        });

        // 5. Build HTTP request
        let full_uri = format!("https://{}:{}{}", host, port, path);
        let mut request = http::Request::builder()
            .method(method)
            .uri(&full_uri)
            .version(http::Version::HTTP_3)
            .body(())?;
        *request.headers_mut() = headers;

        // 6. Send request
        let mut req_stream = send_request.send_request(request).await?;

        // 7. Send body if present
        if let Some(data) = body {
            req_stream.send_data(data).await?;
        }
        req_stream.finish().await?;

        // 8. Receive response
        let response = req_stream.recv_response().await?;
        let status = response.status().as_u16();
        let resp_headers = response.headers().clone();

        // 9. Collect response body
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
    async fn test_http3_client_new() {
        let client = Http3EvasionClient::new();
        assert!(client.is_ok(), "Http3EvasionClient::new() should succeed");
    }
}
