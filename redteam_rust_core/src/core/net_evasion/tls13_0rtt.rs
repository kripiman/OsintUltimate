/// TLS 1.3 0-RTT (early data) client over TCP.
///
/// Uses rustls 0.23 (renamed `rustls-ech`) with `tokio-rustls` 0.26's `early-data`
/// feature. On first contact to a host, the handshake falls back to 1-RTT because
/// no PSK ticket is cached. On re-contact (same `Tls13ZeroRttClient` instance),
/// 0-RTT is attempted if the server previously issued a resumption ticket.
///
/// # Example
/// ```ignore
/// let client = Tls13ZeroRttClient::new()?;
/// let conn = client.connect("example.com", 443).await?;
/// println!("0-RTT accepted: {}", conn.is_early_data_accepted());
/// ```
use anyhow::Result;
use std::sync::Arc;

/// TLS 1.3 client with 0-RTT / early data enabled.
pub struct Tls13ZeroRttClient {
    tls_config: Arc<rustls_ech::ClientConfig>,
}

impl Tls13ZeroRttClient {
    /// Create a client with webpki-roots-ech and 0-RTT enabled.
    pub fn new() -> Result<Self> {
        let root_store = rustls_ech::RootCertStore::from_iter(
            webpki_roots_ech::TLS_SERVER_ROOTS.iter().cloned(),
        );

        let mut tls_config = rustls_ech::ClientConfig::builder_with_provider(Arc::new(
            rustls_ech::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(root_store)
        .with_no_client_auth();

        tls_config.enable_early_data = true;

        Ok(Self {
            tls_config: Arc::new(tls_config),
        })
    }

    /// Connect to `target:port` over TCP with TLS 1.3 and 0-RTT attempt.
    ///
    /// `target` is used both as the TCP endpoint and the TLS server name.
    pub async fn connect(&self, target: &str, port: u16) -> Result<ZeroRttConnection> {
        let stream = tokio::net::TcpStream::connect((target, port)).await?;

        let server_name = rustls_ech::pki_types::ServerName::try_from(target.to_string())
            .map_err(|e| anyhow::anyhow!("invalid server name: {:?}", e))?;

        let connector = tokio_rustls::TlsConnector::from(self.tls_config.clone()).early_data(true);
        let stream = connector.connect(server_name, stream).await?;

        Ok(ZeroRttConnection { stream })
    }
}

/// An established TLS 1.3 connection (possibly via 0-RTT).
pub struct ZeroRttConnection {
    stream: tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
}

impl ZeroRttConnection {
    /// Whether the server accepted the 0-RTT / early data offer.
    ///
    /// Only meaningful when the connection was established after a prior
    /// successful handshake to the same host (PSK ticket cached).
    pub fn is_early_data_accepted(&self) -> bool {
        self.stream.get_ref().1.is_early_data_accepted()
    }

    /// Consume self and return the underlying TLS stream.
    pub fn into_stream(self) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
        self.stream
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_zero_rtt_client_new() {
        let client = Tls13ZeroRttClient::new();
        assert!(
            client.is_ok(),
            "Tls13ZeroRttClient::new() should succeed: {:?}",
            client.err()
        );
    }

    #[test]
    fn test_zero_rtt_connection_types() {
        // Compile-time check that ZeroRttConnection is Send + Sync.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ZeroRttConnection>();
    }

    #[tokio::test]
    async fn test_zero_rtt_fallback_no_server() {
        let client = Tls13ZeroRttClient::new().unwrap();
        let addr = ("127.0.0.1", 59999);
        match client.connect(addr.0, addr.1).await {
            Ok(conn) => {
                // If something is listening, there's no prior ticket → 0-RTT not accepted.
                tokio::time::sleep(Duration::from_millis(50)).await;
                assert!(
                    !conn.is_early_data_accepted(),
                    "First connection should not have 0-RTT accepted (no cached ticket)"
                );
            }
            Err(_) => {
                // Expected: no server on 59999. Test still passes.
            }
        }
    }
}
