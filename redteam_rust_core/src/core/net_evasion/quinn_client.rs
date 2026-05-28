/// Full QUIC transport client using `quinn` 0.10.
///
/// Performs complete TLS 1.3 handshakes over QUIC (RFC 9000 / RFC 9001).
/// Integrates with JA4 spoofing via `with_rustls_config` for custom TLS configs.
use anyhow::Result;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// QUIC evasion client wrapping a `quinn::Endpoint`.
pub struct QuinnEvasionClient {
    endpoint: quinn::Endpoint,
}

impl QuinnEvasionClient {
    /// Create a client with system root CAs (webpki-roots).
    pub fn new() -> Result<Self> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
            rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        }));

        let client_config = quinn::ClientConfig::with_root_certificates(roots);

        let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;
        endpoint.set_default_client_config(client_config);

        Ok(Self { endpoint })
    }

    /// Create a client with a custom `rustls::ClientConfig` (e.g., JA4-spoofed).
    /// Takes ownership of the rustls config; wraps in `Arc` internally.
    pub fn with_rustls_config(tls_config: rustls::ClientConfig) -> Result<Self> {
        let client_config = quinn::ClientConfig::new(Arc::new(tls_config));

        let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;
        endpoint.set_default_client_config(client_config);

        Ok(Self { endpoint })
    }

    /// Connect to a QUIC server at `addr` with `server_name` for SNI.
    /// Completes the full TLS 1.3 handshake.
    pub async fn connect(&self, addr: SocketAddr, server_name: &str) -> Result<QuinnConnection> {
        let connecting = self.endpoint.connect(addr, server_name)?;
        let conn = connecting.await?;
        Ok(QuinnConnection {
            conn,
            was_0rtt: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Create a client with 0-RTT / early data enabled.
    pub fn with_early_data() -> Result<Self> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
            rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        }));

        let mut rustls_config = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(roots)
            .with_no_client_auth();
        rustls_config.enable_early_data = true;

        let client_config = quinn::ClientConfig::new(Arc::new(rustls_config));

        let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;
        endpoint.set_default_client_config(client_config);

        Ok(Self { endpoint })
    }

    /// Connect with 0-RTT attempt.
    ///
    /// On first contact: falls back to 1-RTT (no error).
    /// On re-contact (cached ticket): returns connection immediately.
    /// Call `QuinnConnection::was_0rtt_accepted()` to query result.
    pub async fn connect_0rtt(
        &self,
        addr: SocketAddr,
        server_name: &str,
    ) -> Result<QuinnConnection> {
        let connecting = self.endpoint.connect(addr, server_name)?;
        let was_0rtt = Arc::new(AtomicBool::new(false));
        match connecting.into_0rtt() {
            Ok((conn, accepted)) => {
                let flag = was_0rtt.clone();
                tokio::spawn(async move {
                    if accepted.await {
                        flag.store(true, Ordering::Relaxed);
                    }
                });
                Ok(QuinnConnection { conn, was_0rtt })
            }
            Err(connecting) => {
                let conn = connecting.await?;
                Ok(QuinnConnection { conn, was_0rtt })
            }
        }
    }
}

/// A handle to an established QUIC connection.
#[derive(Clone)]
pub struct QuinnConnection {
    conn: quinn::Connection,
    was_0rtt: Arc<AtomicBool>,
}

impl QuinnConnection {
    /// Open a bidirectional stream.
    pub async fn open_bi(&self) -> Result<(quinn::SendStream, quinn::RecvStream)> {
        let (send, recv) = self.conn.open_bi().await?;
        Ok((send, recv))
    }

    /// Close the connection with an error code and reason.
    pub fn close(&self, error_code: quinn::VarInt, reason: &[u8]) {
        self.conn.close(error_code, reason);
    }

    /// Current smoothed RTT.
    pub fn rtt(&self) -> Duration {
        self.conn.stats().path.rtt
    }

    /// Whether this connection was established with 0-RTT accepted by the server.
    /// Only meaningful when created via `connect_0rtt()`.
    pub fn was_0rtt_accepted(&self) -> bool {
        self.was_0rtt.load(Ordering::Relaxed)
    }

    /// Consume self to return the underlying `quinn::Connection`.
    /// Required by `http3_client.rs` to build `h3_quinn::Connection`.
    pub fn into_connection(self) -> quinn::Connection {
        self.conn
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_quinn_client_new() {
        let client = QuinnEvasionClient::new();
        assert!(
            client.is_ok(),
            "QuinnEvasionClient::new() should succeed: {:?}",
            client.err()
        );
    }

    #[tokio::test]
    async fn test_quinn_client_with_early_data() {
        let client = QuinnEvasionClient::with_early_data();
        assert!(
            client.is_ok(),
            "QuinnEvasionClient::with_early_data() should succeed: {:?}",
            client.err()
        );
    }

    #[tokio::test]
    async fn test_0rtt_no_ticket() {
        let client = QuinnEvasionClient::with_early_data().unwrap();
        // localhost:9999 has no server — connection will fail, but we can verify
        // the connect_0rtt path doesn't panic and returns was_0rtt=false.
        let addr: SocketAddr = "127.0.0.1:59999".parse().unwrap();
        let result = client.connect_0rtt(addr, "localhost").await;
        if let Ok(conn) = result {
            // Give the background task a moment to settle
            tokio::time::sleep(Duration::from_millis(50)).await;
            assert!(
                !conn.was_0rtt_accepted(),
                "First connection should not have 0-RTT accepted"
            );
        }
        // If connection fails, that's expected (no server). Test still passes.
    }

    #[test]
    fn test_quinn_connection_clone() {
        fn assert_clone<T: Clone>() {}
        assert_clone::<QuinnConnection>();
    }
}
