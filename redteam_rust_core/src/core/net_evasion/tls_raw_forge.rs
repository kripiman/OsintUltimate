/// Raw TLS ClientHello forge for exact JA4 fingerprint matching.
///
/// Bypasses rustls entirely and crafts bytes manually, giving full control
/// over cipher suites, extensions, and record-layer headers.
///
/// # Usage
/// ```
/// let forge = ClientHelloForge::new();
/// let bytes = forge.build();
/// // Send bytes over raw TCP socket
/// ```
#[derive(Debug, Clone)]
pub struct ClientHelloForge {
    /// TLS record-layer version (0x0301 for TLS 1.3 compat, 0x0303 for TLS 1.2).
    pub record_version: u16,
    /// ClientHello version (0x0303 = TLS 1.2 even for TLS 1.3).
    pub version: u16,
    /// 32-byte random.
    pub random: [u8; 32],
    /// Session ID (length automatically encoded).
    pub session_id: Vec<u8>,
    /// Cipher suite IDs in preference order.
    pub cipher_suites: Vec<u16>,
    /// Extensions as (type, raw_data) pairs.
    pub extensions: Vec<(u16, Vec<u8>)>,
}

impl Default for ClientHelloForge {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientHelloForge {
    /// Create a minimal ClientHello forge with sensible defaults.
    pub fn new() -> Self {
        Self {
            record_version: 0x0301,
            version: 0x0303,
            random: rand::random(),
            session_id: Vec::new(),
            cipher_suites: Vec::new(),
            extensions: Vec::new(),
        }
    }

    /// Build the raw TLS record bytes ready to send over TCP.
    pub fn build(&self) -> Vec<u8> {
        // --- ClientHello body ---
        let mut body = Vec::new();

        // Version
        body.extend_from_slice(&self.version.to_be_bytes());

        // Random
        body.extend_from_slice(&self.random);

        // Session ID (length + data)
        body.push(self.session_id.len() as u8);
        body.extend_from_slice(&self.session_id);

        // Cipher suites: 2-byte length + list
        let cipher_len = self.cipher_suites.len() * 2;
        body.extend_from_slice(&(cipher_len as u16).to_be_bytes());
        for &cs in &self.cipher_suites {
            body.extend_from_slice(&cs.to_be_bytes());
        }

        // Compression methods: 1-byte length + null
        body.push(1);
        body.push(0);

        // Extensions: 2-byte length + list
        let mut ext_bytes = Vec::new();
        for (ext_type, ext_data) in &self.extensions {
            ext_bytes.extend_from_slice(&ext_type.to_be_bytes());
            ext_bytes.extend_from_slice(&(ext_data.len() as u16).to_be_bytes());
            ext_bytes.extend_from_slice(ext_data);
        }
        body.extend_from_slice(&(ext_bytes.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext_bytes);

        // --- Handshake header ---
        let mut handshake = Vec::new();
        handshake.push(0x01); // ClientHello
        let len = body.len();
        handshake.push(((len >> 16) & 0xff) as u8);
        handshake.push(((len >> 8) & 0xff) as u8);
        handshake.push((len & 0xff) as u8);
        handshake.extend_from_slice(&body);

        // --- TLS record layer ---
        let mut record = Vec::new();
        record.push(0x16); // Handshake content type
        record.extend_from_slice(&self.record_version.to_be_bytes());
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);

        record
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_hello_build_minimal() {
        let mut forge = ClientHelloForge::new();
        forge.cipher_suites = vec![0x1301];
        let bytes = forge.build();

        // Record type = handshake
        assert_eq!(bytes[0], 0x16);
        // Handshake type = ClientHello
        assert_eq!(bytes[5], 0x01);
        // Version = 0x0303
        assert_eq!(&bytes[9..=10], &[0x03, 0x03]);
    }

    #[test]
    fn test_client_hello_with_extensions() {
        let mut forge = ClientHelloForge::new();
        forge.cipher_suites = vec![0x1301];
        forge.extensions.push((0x002b, vec![0x03, 0x03, 0x04])); // supported_versions
        let bytes = forge.build();

        // Should be parsable by tls-parser
        let result = tls_parser::parse_tls_plaintext(&bytes);
        assert!(result.is_ok());
    }
}
