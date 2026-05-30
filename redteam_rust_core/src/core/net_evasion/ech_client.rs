/// Encrypted Client Hello (ECH) capable TLS client over TCP.
///
/// Uses rustls 0.23 (renamed `rustls-ech`) with the `aws_lc_rs` crypto provider,
/// which is required for HPKE support. ECH encrypts the Server Name Indication
/// (SNI) in the TLS ClientHello, preventing on-path observers from learning the
/// target hostname.
///
/// # Example
/// ```ignore
/// let client = EchClient::with_ech_config(&ech_config_bytes)?;
/// let conn = client.connect("cloudflare-ech.com", 443).await?;
/// println!("ECH status: {:?}", conn.ech_status());
/// ```
use anyhow::Result;
use std::sync::Arc;

/// ECH-enabled TLS client.
pub struct EchClient {
    tls_config: Arc<rustls_ech::ClientConfig>,
}

impl EchClient {
    /// Create a plain TLS 1.3 client with webpki-roots-ech (no ECH).
    pub fn new() -> Result<Self> {
        let root_store = rustls_ech::RootCertStore::from_iter(
            webpki_roots_ech::TLS_SERVER_ROOTS.iter().cloned(),
        );

        let tls_config = rustls_ech::ClientConfig::builder_with_provider(Arc::new(
            rustls_ech::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(root_store)
        .with_no_client_auth();

        Ok(Self {
            tls_config: Arc::new(tls_config),
        })
    }

    /// Create a client with an ECH configuration.
    ///
    /// The `ech_config_bytes` should be the raw ECHConfigList bytes
    /// (e.g. from a DNS HTTPS resource record, base64-decoded).
    pub fn with_ech_config(ech_config_bytes: &[u8]) -> Result<Self> {
        let ech_config = rustls_ech::client::EchConfig::new(
            ech_config_bytes.into(),
            rustls_ech::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES,
        )
        .map_err(|e| anyhow::anyhow!("ECH config parsing failed: {:?}", e))?;

        let root_store = rustls_ech::RootCertStore::from_iter(
            webpki_roots_ech::TLS_SERVER_ROOTS.iter().cloned(),
        );

        let tls_config = rustls_ech::ClientConfig::builder_with_provider(Arc::new(
            rustls_ech::crypto::aws_lc_rs::default_provider(),
        ))
        .with_ech(rustls_ech::client::EchMode::Enable(ech_config))?
        .with_root_certificates(root_store)
        .with_no_client_auth();

        Ok(Self {
            tls_config: Arc::new(tls_config),
        })
    }

    /// Connect to `target:port` over TCP with (optionally ECH-enabled) TLS.
    ///
    /// `target` is used both as the TCP endpoint and the TLS server name.
    pub async fn connect(&self, target: &str, port: u16) -> Result<EchConnection> {
        let stream = tokio::net::TcpStream::connect((target, port)).await?;

        let server_name = rustls_ech::pki_types::ServerName::try_from(target.to_string())
            .map_err(|e| anyhow::anyhow!("invalid server name: {:?}", e))?;

        let connector = tokio_rustls::TlsConnector::from(self.tls_config.clone());
        let stream = connector.connect(server_name, stream).await?;

        Ok(EchConnection { stream })
    }
}

/// An established ECH-enabled TLS connection.
pub struct EchConnection {
    stream: tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
}

impl EchConnection {
    /// Return the ECH status of this connection.
    ///
    /// Only meaningful after the handshake completes.
    pub fn ech_status(&self) -> rustls_ech::client::EchStatus {
        self.stream.get_ref().1.ech_status()
    }

    /// Consume self and return the underlying TLS stream.
    pub fn into_stream(self) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
        self.stream
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ech_client_new() {
        let client = EchClient::new();
        assert!(client.is_ok(), "EchClient::new() should succeed: {:?}", client.err());
    }

    #[test]
    fn test_ech_client_with_bad_ech_config() {
        // Random bytes are not a valid ECHConfigList → should fail parsing.
        let bad_bytes = b"\x00\x01\x02\x03\x04\x05";
        let client = EchClient::with_ech_config(bad_bytes);
        assert!(
            client.is_err(),
            "Invalid ECH config bytes should fail parsing"
        );
    }

    #[test]
    fn test_ech_connection_types() {
        // Compile-time check that EchConnection is Send + Sync.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<EchConnection>();
    }
}
