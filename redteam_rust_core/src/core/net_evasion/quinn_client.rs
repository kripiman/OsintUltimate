/// Full QUIC transport client using `quinn` 0.10.
///
/// Performs complete TLS 1.3 handshakes over QUIC (RFC 9000 / RFC 9001).
/// Integrates with JA4 spoofing via `with_rustls_config` for custom TLS configs.
use anyhow::Result;
use std::net::SocketAddr;
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
        Ok(QuinnConnection { conn })
    }
}

/// A handle to an established QUIC connection.
#[derive(Clone)]
pub struct QuinnConnection {
    conn: quinn::Connection,
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

    #[test]
    fn test_quinn_connection_clone() {
        // We can't easily create a real connection without a server,
        // but we can verify Clone is derived by type-checking.
        fn assert_clone<T: Clone>() {}
        assert_clone::<QuinnConnection>();
    }
}
