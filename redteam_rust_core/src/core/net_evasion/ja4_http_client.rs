use crate::core::net_evasion::ja4_spoofer::Ja4Spoofer;
use crate::core::net_evasion::{EvasionResult, NetEvasionStrategy};
use anyhow::Result;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// HTTP client with active JA4 fingerprint spoofing.
///
/// # Two-tier design
/// * **Tier 1** (`get`): Full HTTPS request via reqwest with a rustls config
///   that approximates the target JA4. Fast and usable for real traffic.
/// * **Tier 2** (`fingerprint_probe`): Sends a raw forged ClientHello over TCP,
///   captures the ServerHello, and aborts. Exact JA4 match, but no HTTP.
#[derive(Debug, Clone)]
pub struct Ja4EvasionClient {
    inner: reqwest::Client,
    ja4_used: String,
    spoofer: Ja4Spoofer,
}

impl Ja4EvasionClient {
    /// Creates an HTTP client configured to approximate `target_ja4`.
    pub fn new(target_ja4: &str) -> Result<Self> {
        let spoofer = Ja4Spoofer::from_ja4(target_ja4)?;
        let rustls_config = spoofer.to_rustls_config()?;

        let client = reqwest::Client::builder()
            .use_rustls_tls()
            .use_preconfigured_tls(rustls_config)
            .timeout(Duration::from_secs(30))
            .build()?;

        Ok(Self {
            inner: client,
            ja4_used: target_ja4.to_string(),
            spoofer,
        })
    }

    /// **Tier 1** — Performs a GET request with the JA4-spoofed rustls config.
    ///
    /// If the NGFW permits the approximated fingerprint, a full HTTP response
    /// is returned. TLS handshake failures may indicate fingerprint blocking.
    pub async fn get(&self, url: &str) -> Result<reqwest::Response> {
        let resp = self.inner.get(url).send().await?;
        Ok(resp)
    }

    /// **Tier 2** — Sends a raw forged ClientHello with exact JA4 match.
    ///
    /// Probe-only: opens a TCP connection, sends the forged ClientHello,
    /// reads the ServerHello, and immediately drops the connection.
    /// No key exchange is performed.
    ///
    /// Returns an [`EvasionResult`] whose `success` field is `true` when:
    /// 1. The locally-computed JA4 of the forged ClientHello matches `target_ja4`, **and**
    /// 2. The server responds with a valid ServerHello (not an alert).
    pub async fn fingerprint_probe(&self, target: &str) -> Result<EvasionResult> {
        let start = std::time::Instant::now();

        // Parse host:port
        let (host, port) = if let Some(colon) = target.rfind(':') {
            let h = &target[..colon];
            let p = target[colon + 1..].parse::<u16>()?;
            (h.to_string(), p)
        } else {
            (target.to_string(), 443)
        };

        // Build forged ClientHello
        let forge = self.spoofer.to_client_hello_forge(&host)?;
        let client_hello = forge.build();

        // Local JA4 verification
        let computed_ja4 = crate::utils::ja4::calculate_ja4(&client_hello)?;
        let ja4_matches = computed_ja4 == self.ja4_used;

        // Resolve and connect
        let addr = tokio::net::lookup_host((host.as_str(), port))
            .await?
            .next()
            .ok_or_else(|| anyhow::anyhow!("DNS resolution failed for {}", host))?;

        let mut stream = tokio::net::TcpStream::connect(addr).await?;

        // Send + receive with timeout
        let probe_result = tokio::time::timeout(Duration::from_secs(5), async {
            stream.write_all(&client_hello).await?;

            let mut buf = vec![0u8; 16384];
            let n = stream.read(&mut buf).await?;
            buf.truncate(n);

            // Look for ServerHello in response
            let has_server_hello = Self::contains_server_hello(&buf);
            Ok::<bool, anyhow::Error>(has_server_hello)
        })
        .await;

        let has_server_hello = matches!(probe_result, Ok(Ok(true)));

        let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

        Ok(EvasionResult {
            strategy_used: NetEvasionStrategy::Ja4Spoofing,
            success: ja4_matches && has_server_hello,
            packets_sent: 1,
            response_received: has_server_hello,
            latency_ms,
        })
    }

    fn contains_server_hello(buf: &[u8]) -> bool {
        if buf.is_empty() {
            return false;
        }
        match tls_parser::parse_tls_plaintext(buf) {
            Ok((_, plaintext)) => {
                for msg in plaintext.msg {
                    if let tls_parser::TlsMessage::Handshake(
                        tls_parser::TlsMessageHandshake::ServerHello(_),
                    ) = msg
                    {
                        return true;
                    }
                }
                false
            }
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_construction() {
        let client = Ja4EvasionClient::new("t13d1516h2_8daaf6152771_e5627efa2ab1");
        assert!(client.is_ok());
    }



    #[test]
    fn test_unknown_ja4_fallback() {
        let client = Ja4EvasionClient::new("t99i0000xx_000000000000_000000000000");
        assert!(client.is_ok());
    }
}
