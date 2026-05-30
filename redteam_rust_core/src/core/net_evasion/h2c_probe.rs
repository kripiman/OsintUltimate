/// HTTP/2 cleartext (h2c) upgrade probe.
///
/// Detects whether a target accepts HTTP/2 upgrade over plaintext TCP.
/// Servers that accept h2c may allow HTTP/2 traffic to bypass WAFs that only
/// inspect HTTP/1.1.
///
/// # Example
/// ```ignore
/// let result = H2cProbeClient::probe_h2c("target.com", 80).await?;
/// if result.h2c_accepted {
///     println!("h2c upgrade accepted — WAF bypass possible");
/// }
/// ```
use anyhow::Result;
use std::time::Duration;
use tokio::io::AsyncReadExt;

/// Result of an h2c upgrade probe.
#[derive(Debug, Clone)]
pub struct H2cProbeResult {
    /// Whether the server returned `101 Switching Protocols`.
    pub h2c_accepted: bool,
    /// The HTTP status code received.
    pub response_status: u16,
    /// The `Server` header value, if present.
    pub server_header: Option<String>,
}

/// Probe for HTTP/2 cleartext upgrade support.
pub struct H2cProbeClient;

impl H2cProbeClient {
    /// Probe `target:port` for h2c upgrade acceptance.
    ///
    /// Sends an HTTP/1.1 GET request with `Upgrade: h2c` and
    /// `HTTP2-Settings` headers. A `101 Switching Protocols` response
    /// indicates the server supports h2c upgrade.
    pub async fn probe_h2c(target: &str, port: u16) -> Result<H2cProbeResult> {
        let stream = tokio::net::TcpStream::connect((target, port)).await?;

        let request = format!(
            "GET / HTTP/1.1\r\n\
             Host: {target}\r\n\
             Upgrade: h2c\r\n\
             HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\r\n\
             Connection: Upgrade, HTTP2-Settings\r\n\
             User-Agent: Mozilla/5.0\r\n\
             \r\n"
        );

        let (mut rx, mut tx) = stream.into_split();
        tokio::io::AsyncWriteExt::write_all(&mut tx, request.as_bytes()).await?;
        // Flush to ensure the server receives the full request.
        tokio::io::AsyncWriteExt::flush(&mut tx).await?;

        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(10), rx.read(&mut buf)).await
            .map_err(|_| anyhow::anyhow!("h2c probe response timeout"))?
            .map_err(|e| anyhow::anyhow!("h2c probe read failed: {e:?}"))?;
        drop(tx);

        let response = String::from_utf8_lossy(&buf[..n]);
        let status = Self::parse_status(&response).unwrap_or(0);
        let server = Self::parse_header(&response, "Server");

        Ok(H2cProbeResult {
            h2c_accepted: status == 101,
            response_status: status,
            server_header: server,
        })
    }

    fn parse_status(response: &str) -> Option<u16> {
        let first_line = response.lines().next()?;
        let parts: Vec<&str> = first_line.split_whitespace().collect();
        if parts.len() >= 2 {
            parts[1].parse().ok()
        } else {
            None
        }
    }

    fn parse_header(response: &str, name: &str) -> Option<String> {
        let prefix = format!("{name}: ");
        for line in response.lines() {
            if line.to_lowercase().starts_with(&prefix.to_lowercase()) {
                return Some(line[prefix.len()..].trim().to_string());
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_h2c_probe_no_server() {
        let result = H2cProbeClient::probe_h2c("127.0.0.1", 59999).await;
        // No server → connection refused → should return Err.
        assert!(
            result.is_err(),
            "h2c probe to nothing should fail: {:?}",
            result.ok()
        );
    }

    #[test]
    fn test_parse_status_ok() {
        let resp = "HTTP/1.1 101 Switching Protocols\r\n";
        assert_eq!(H2cProbeClient::parse_status(resp), Some(101));
    }

    #[test]
    fn test_parse_status_not_found() {
        let resp = "HTTP/1.1 404 Not Found\r\n";
        assert_eq!(H2cProbeClient::parse_status(resp), Some(404));
    }

    #[test]
    fn test_parse_header_server() {
        let resp = "HTTP/1.1 200 OK\r\nServer: nginx/1.24\r\n\r\n";
        assert_eq!(
            H2cProbeClient::parse_header(resp, "Server"),
            Some("nginx/1.24".to_string())
        );
    }

    #[test]
    fn test_h2c_probe_result_types() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<H2cProbeResult>();
    }
}
