use crate::core::net_evasion::tls_raw_forge::ClientHelloForge;
use crate::utils::ja4::{parse_ja4, Ja4Components};
use anyhow::Result;
use rustls::{ClientConfig, OwnedTrustAnchor, RootCertStore};

/// Known browser TLS profile used for JA4 approximation.
#[derive(Debug, Clone)]
struct BrowserProfile {
    /// The JA4_a prefix (first 10 chars of full JA4).
    ja4_a: &'static str,
    /// Cipher suite IDs in the order the browser sends them.
    cipher_suites: &'static [u16],
    /// Extension types the browser includes (count must match JA4_a).
    extensions: &'static [u16],
    /// ALPN protocol bytes (e.g. b"h2").
    alpn: &'static [u8],
    /// TLS version to advertise.
    _tls_version: &'static rustls::SupportedProtocolVersion,
}

/// Hard-coded presets for well-known browsers.
/// In Sprint 6 these will be replaced by a dynamic JA4 database.
static BROWSER_PRESETS: &[BrowserProfile] = &[
    // Chrome 120 (TLS 1.3, SNI=domain, ~15 extensions, 16 ciphers, ALPN=h2)
    BrowserProfile {
        ja4_a: "t13d1516h2",
        cipher_suites: &[
            0x1301, 0x1302, 0x1303, // TLS 1.3 AEAD
            0xc02b, 0xc02f, 0xc02c, 0xc030, // ECDHE + AES-GCM
            0xcca9, 0xcca8, // ECDHE + ChaCha20
            0xc013, 0xc014, // ECDHE + AES-CBC
            0x009c, 0x009d, // RSA + AES-GCM
            0x002f, 0x0035, // RSA + AES-CBC
            0x000a,         // RSA + 3DES
        ],
        extensions: &[
            0,      // server_name
            23,     // extended_master_secret
            65281,  // renegotiation_info
            10,     // supported_groups
            11,     // ec_point_formats
            35,     // session_ticket
            16,     // alpn
            5,      // status_request
            13,     // signature_algorithms
            18,     // signed_certificate_timestamp
            51,     // key_share
            43,     // supported_versions
            44,     // cookie
            45,     // psk_key_exchange_modes
            47,     // certificate_authorities
        ],
        alpn: b"h2",
        _tls_version: &rustls::version::TLS13,
    },
    // Firefox 121 (TLS 1.3, SNI=domain, ~14 extensions, ~13 ciphers, ALPN=h2)
    BrowserProfile {
        ja4_a: "t13d1413h2",
        cipher_suites: &[
            0x1301, 0x1303, 0x1302, // TLS 1.3
            0xc02b, 0xc02f, 0xcca9, 0xcca8,
            0xc02c, 0xc030, 0xc00a, 0xc009,
            0xc013, 0xc014,
        ],
        extensions: &[
            0, 23, 65281, 10, 11, 35, 16,
            5, 13, 18, 51, 43, 45, 27,
        ],
        alpn: b"h2",
        _tls_version: &rustls::version::TLS13,
    },
];

/// Active JA4 spoofer.
///
/// * **Tier 1:** Produces a `rustls::ClientConfig` that approximates the target JA4.
/// * **Tier 2:** Produces a raw `ClientHelloForge` for exact byte-level matching.
#[derive(Debug, Clone)]
pub struct Ja4Spoofer {
    _target_ja4: String,
    components: Ja4Components,
    preset: Option<&'static BrowserProfile>,
}

impl Ja4Spoofer {
    /// Parse a target JA4 and look up a matching browser preset.
    pub fn from_ja4(target: &str) -> Result<Self> {
        let components = parse_ja4(target)?;
        let preset = BROWSER_PRESETS
            .iter()
            .find(|p| target.starts_with(p.ja4_a));

        Ok(Self {
            _target_ja4: target.to_string(),
            components,
            preset,
        })
    }

    /// Returns the parsed JA4 components.
    pub fn components(&self) -> &Ja4Components {
        &self.components
    }

    /// Whether a full preset is available for this JA4.
    pub fn has_preset(&self) -> bool {
        self.preset.is_some()
    }

    /// Build a rustls `ClientConfig` that approximates the target JA4.
    ///
    /// # Limitations
    /// - rustls only supports 9 cipher suites, so `cipher_count` can never match
    ///   targets with >9 ciphers (e.g. Chrome 120 has 16).
    /// - rustls does not expose direct extension control.
    /// - rustls does not emit GREASE values.
    pub fn to_rustls_config(&self) -> Result<ClientConfig> {
        let mut root_store = RootCertStore::empty();
        root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
            OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        }));

        // TLS version
        let versions = match self.components.tls_version.as_str() {
            "13" => vec![&rustls::version::TLS13],
            "12" => vec![&rustls::version::TLS12],
            _ => vec![&rustls::version::TLS13, &rustls::version::TLS12],
        };

        // Cipher suites — filter to those rustls actually supports
        let wanted_ids: Vec<u16> = if let Some(preset) = self.preset {
            preset.cipher_suites.to_vec()
        } else {
            rustls::DEFAULT_CIPHER_SUITES
                .iter()
                .map(|s| s.suite().get_u16())
                .collect()
        };

        let cipher_suites: Vec<rustls::SupportedCipherSuite> = wanted_ids
            .iter()
            .filter_map(|&id| {
                rustls::ALL_CIPHER_SUITES
                    .iter()
                    .find(|s| s.suite().get_u16() == id)
                    .copied()
            })
            .collect();

        let config = if cipher_suites.is_empty() {
            ClientConfig::builder()
                .with_safe_defaults()
                .with_root_certificates(root_store)
                .with_no_client_auth()
        } else {
            ClientConfig::builder()
                .with_cipher_suites(&cipher_suites)
                .with_safe_default_kx_groups()
                .with_protocol_versions(&versions)?
                .with_root_certificates(root_store)
                .with_no_client_auth()
        };

        // ALPN must be set after construction (it's a public field in 0.21)
        let mut config = config;
        config.alpn_protocols = vec![self.components.alpn.as_bytes().to_vec()];

        Ok(config)
    }

    /// Build a raw `ClientHelloForge` for exact JA4 matching.
    ///
    /// If a preset is available, the forge uses the exact cipher and extension
    /// list from the preset. Otherwise it builds a generic ClientHello.
    pub fn to_client_hello_forge(&self, sni_hostname: &str) -> Result<ClientHelloForge> {
        let mut forge = ClientHelloForge::new();
        forge.record_version = 0x0301;
        forge.version = 0x0303;

        if let Some(preset) = self.preset {
            forge.cipher_suites = preset.cipher_suites.to_vec();

            // SNI (type 0)
            if preset.extensions.contains(&0) {
                forge.extensions.push((0, build_sni_ext(sni_hostname)));
            }

            // ALPN (type 16)
            if preset.extensions.contains(&16) {
                forge.extensions.push((16, build_alpn_ext(&[preset.alpn])));
            }

            // Supported groups (type 10)
            if preset.extensions.contains(&10) {
                let groups = [0x001du16, 0x0017, 0x0018]; // x25519, secp256r1, secp384r1
                let mut data = Vec::new();
                data.extend_from_slice(&(groups.len() as u16 * 2).to_be_bytes());
                for g in groups {
                    data.extend_from_slice(&g.to_be_bytes());
                }
                forge.extensions.push((10, data));
            }

            // EC point formats (type 11)
            if preset.extensions.contains(&11) {
                let formats = [0x00u8]; // uncompressed
                let mut data = Vec::new();
                data.push(formats.len() as u8);
                data.extend_from_slice(&formats);
                forge.extensions.push((11, data));
            }

            // Supported versions (type 43)
            if preset.extensions.contains(&43) {
                let versions = [0x0304u16, 0x0303]; // TLS 1.3, TLS 1.2
                let mut data = Vec::new();
                data.push(versions.len() as u8 * 2);
                for v in versions {
                    data.extend_from_slice(&v.to_be_bytes());
                }
                forge.extensions.push((43, data));
            }

            // Signature algorithms (type 13)
            if preset.extensions.contains(&13) {
                let algs = [
                    0x0403u16, // ecdsa_secp256r1_sha256
                    0x0804,    // rsa_pss_rsae_sha256
                    0x0401,    // rsa_pkcs1_sha256
                    0x0503,    // ecdsa_secp384r1_sha384
                    0x0805,    // rsa_pss_rsae_sha384
                    0x0501,    // rsa_pkcs1_sha384
                    0x0806,    // rsa_pss_rsae_sha512
                    0x0601,    // rsa_pkcs1_sha512
                ];
                let mut data = Vec::new();
                data.extend_from_slice(&(algs.len() as u16 * 2).to_be_bytes());
                for a in algs {
                    data.extend_from_slice(&a.to_be_bytes());
                }
                forge.extensions.push((13, data));
            }

            // Key share (type 51) — dummy X25519 public key
            if preset.extensions.contains(&51) {
                let dummy_key: [u8; 32] = rand::random();
                let mut data = Vec::new();
                // Total length of key_share list = 2 (group) + 2 (key len) + 32 (key) = 36
                data.extend_from_slice(&36u16.to_be_bytes());
                data.extend_from_slice(&0x001du16.to_be_bytes()); // x25519
                data.extend_from_slice(&32u16.to_be_bytes());
                data.extend_from_slice(&dummy_key);
                forge.extensions.push((51, data));
            }

            // PSK key exchange modes (type 45)
            if preset.extensions.contains(&45) {
                let data = vec![1, 1]; // length, psk_dhe_ke
                forge.extensions.push((45, data));
            }

            // Extended master secret (type 23)
            if preset.extensions.contains(&23) {
                forge.extensions.push((23, Vec::new()));
            }

            // Renegotiation info (type 65281)
            if preset.extensions.contains(&65281) {
                forge.extensions.push((65281, vec![0x00]));
            }

            // Session ticket (type 35)
            if preset.extensions.contains(&35) {
                forge.extensions.push((35, Vec::new()));
            }

            // Status request (type 5)
            if preset.extensions.contains(&5) {
                let data = vec![0x01, 0x00, 0x00, 0x00, 0x00];
                forge.extensions.push((5, data));
            }

            // Signed certificate timestamp (type 18)
            if preset.extensions.contains(&18) {
                forge.extensions.push((18, Vec::new()));
            }

            // Cookie (type 44)
            if preset.extensions.contains(&44) {
                forge.extensions.push((44, Vec::new()));
            }

            // Certificate authorities (type 47)
            if preset.extensions.contains(&47) {
                forge.extensions.push((47, Vec::new()));
            }
        } else {
            // Generic fallback when no preset is known
            forge.cipher_suites = vec![0x1301, 0x1302, 0x1303];
            forge.extensions.push((0, build_sni_ext(sni_hostname)));
            forge.extensions.push((16, build_alpn_ext(&[b"h2"])));
            let mut versions = Vec::new();
            versions.push(2u8);
            versions.extend_from_slice(&0x0304u16.to_be_bytes());
            forge.extensions.push((43, versions));
        }

        Ok(forge)
    }
}

fn build_sni_ext(hostname: &str) -> Vec<u8> {
    let mut data = Vec::new();
    let hostname_bytes = hostname.as_bytes();
    let list_len = 1 + 2 + hostname_bytes.len();
    data.extend_from_slice(&(list_len as u16).to_be_bytes());
    data.push(0x00); // name_type = hostname
    data.extend_from_slice(&(hostname_bytes.len() as u16).to_be_bytes());
    data.extend_from_slice(hostname_bytes);
    data
}

fn build_alpn_ext(protocols: &[&[u8]]) -> Vec<u8> {
    let mut list = Vec::new();
    for p in protocols {
        list.push(p.len() as u8);
        list.extend_from_slice(p);
    }
    let mut data = Vec::new();
    data.extend_from_slice(&(list.len() as u16).to_be_bytes());
    data.extend_from_slice(&list);
    data
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::ja4::calculate_ja4;

    #[test]
    fn test_chrome_120_preset_parses() {
        let spoofer = Ja4Spoofer::from_ja4("t13d1516h2_8daaf6152771_e5627efa2ab1").unwrap();
        assert!(spoofer.has_preset());
        assert_eq!(spoofer.components().ext_count, 15);
        assert_eq!(spoofer.components().cipher_count, 16);
    }

    #[test]
    fn test_unknown_ja4_has_no_preset() {
        let spoofer = Ja4Spoofer::from_ja4("t99i0000xx_000000000000_000000000000").unwrap();
        assert!(!spoofer.has_preset());
    }

    #[test]
    fn test_raw_forge_produces_valid_ja4() {
        let spoofer = Ja4Spoofer::from_ja4("t13d1516h2_8daaf6152771_e5627efa2ab1").unwrap();
        let forge = spoofer.to_client_hello_forge("example.com").unwrap();
        let bytes = forge.build();

        // Must be parsable by tls-parser
        let ja4 = calculate_ja4(&bytes).unwrap();
        // JA4_a must match exactly
        assert!(ja4.starts_with("t13d1516h2"), "Expected JA4_a t13d1516h2, got {}", ja4);
    }
}
