/// QUIC-specific evasion and reconnaissance strategies.
///
/// Currently implements Retry token probing to detect stateless load balancers.
use anyhow::Result;
use std::net::SocketAddrV4;
use std::time::Duration;

/// QUIC evasion strategy selector.
#[derive(Debug, Clone, Copy)]
pub enum QuicEvasionStrategy {
    /// Force a Retry handshake and verify the server's token handling.
    RetryTokenProbe,
}

/// Information extracted from a QUIC Retry packet (RFC 9000 §17.2.5).
#[derive(Debug, Clone)]
pub struct RetryInfo {
    pub version: u32,
    pub dst_cid: Vec<u8>,
    pub src_cid: Vec<u8>,
    pub token: Vec<u8>,
}

impl RetryInfo {
    /// Parse a raw QUIC Retry packet.
    ///
    /// Retry layout (Long Header):
    /// Byte 0:  1STTTXXX where S=1, TTT=3 (Retry) → 0xF0..0xFF
    /// Bytes 1-4:   Version (4 bytes BE)
    /// Byte 5:      DCID Len
    /// Bytes 6..:   DCID
    /// Next byte:   SCID Len
    /// Next bytes:  SCID
    /// Remainder-16: Retry Token
    /// Last 16:     Retry Integrity Tag
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < 6 {
            return Err(anyhow::anyhow!("Retry packet too short"));
        }
        // Header Form (bit 7) must be 1, Fixed Bit (bit 6) must be 1,
        // Packet Type (bits 4-5) must be 3 (Retry).
        if buf[0] & 0x80 == 0 || buf[0] & 0x40 == 0 || (buf[0] >> 4) & 0x3 != 0x3 {
            return Err(anyhow::anyhow!("not a Retry packet"));
        }
        let version = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
        let dcil = buf[5] as usize;
        let mut pos = 6;
        if pos + dcil > buf.len() {
            return Err(anyhow::anyhow!("DCID out of bounds"));
        }
        let dst_cid = buf[pos..pos + dcil].to_vec();
        pos += dcil;
        if pos >= buf.len() {
            return Err(anyhow::anyhow!("missing SCID len"));
        }
        let scil = buf[pos] as usize;
        pos += 1;
        if pos + scil > buf.len() {
            return Err(anyhow::anyhow!("SCID out of bounds"));
        }
        let src_cid = buf[pos..pos + scil].to_vec();
        pos += scil;
        // Remainder minus 16 bytes integrity tag = token
        if pos + 16 > buf.len() {
            return Err(anyhow::anyhow!("missing integrity tag"));
        }
        let token = buf[pos..buf.len() - 16].to_vec();
        Ok(RetryInfo {
            version,
            dst_cid,
            src_cid,
            token,
        })
    }
}

/// Result of a Retry token probe.
#[derive(Debug, Clone)]
pub struct RetryProbeResult {
    pub retry_received: bool,
    pub token_extracted: bool,
    pub handshake_completed: bool,
    pub latency_ms: f64,
}

/// Execute a Retry token probe against `target`.
///
/// 1. Send a forged QUIC Initial to `target`.
/// 2. If a Retry is received within timeout, parse it to extract the token.
/// 3. Resend the Initial with the token embedded.
/// 4. Verify the server responds with an Initial/Handshake (not another Retry).
pub async fn retry_token_probe(
    target: SocketAddrV4,
    _version: u32,
) -> Result<RetryProbeResult> {
    use tokio::net::UdpSocket;

    let start = std::time::Instant::now();

    let socket = UdpSocket::bind("0.0.0.0:0").await?;

    // Step 1: Send forged QUIC Initial
    let dcid = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let scid: &[u8] = &[];
    let forge = crate::core::net_evasion::quic_forge::QuicInitialForge::new(&dcid, scid)
        .with_crypto_frame(b"\x16\x03\x01\x00\x05\x01\x00\x00\x01\x03\x03");
    let packet = forge.build()?;
    socket.send_to(&packet, target).await?;

    // Step 2: Wait for Retry with timeout
    let mut buf = vec![0u8; 2048];
    let retry_result = tokio::time::timeout(Duration::from_secs(3), async {
        socket.recv(&mut buf).await
    })
    .await;

    let mut retry_received = false;
    let mut token_extracted = false;
    let mut handshake_completed = false;

    if let Ok(Ok(n)) = retry_result {
        if n > 0 {
            // Check if it's a Retry packet
            if buf[0] & 0x80 != 0 && buf[0] & 0x40 != 0 && (buf[0] >> 4) & 0x3 == 0x3 {
                retry_received = true;
                if let Ok(retry_info) = RetryInfo::parse(&buf[..n]) {
                    token_extracted = !retry_info.token.is_empty();

                    // Step 3: Resend Initial with token
                    // Build a new Initial with the Retry token
                    let new_forge =
                        crate::core::net_evasion::quic_forge::QuicInitialForge::new(&dcid, scid)
                            .with_token(&retry_info.token)
                            .with_crypto_frame(b"\x16\x03\x01\x00\x05\x01\x00\x00\x01\x03\x03");
                    let new_packet = new_forge.build()?;
                    socket.send_to(&new_packet, target).await?;

                    // Step 4: Wait for Initial/Handshake response
                    let response_result = tokio::time::timeout(
                        Duration::from_secs(3),
                        async {
                            let mut rbuf = vec![0u8; 2048];
                            socket.recv(&mut rbuf).await.map(|sz| (sz, rbuf))
                        },
                    )
                    .await;

                    if let Ok(Ok((sz, rbuf))) = response_result {
                        if sz > 0 {
                            // Long header + not Retry → Initial or Handshake
                            let is_long = rbuf[0] & 0x80 != 0;
                            let is_retry =
                                rbuf[0] & 0x40 != 0 && (rbuf[0] >> 4) & 0x3 == 0x3;
                            if is_long && !is_retry {
                                handshake_completed = true;
                            }
                        }
                    }
                }
            }
        }
    }

    let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

    Ok(RetryProbeResult {
        retry_received,
        token_extracted,
        handshake_completed,
        latency_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_retry_packet_parse() {
        // Build a synthetic Retry packet
        let mut packet = Vec::new();
        // First byte: Long Header (1), Fixed Bit (1), Retry type (0b11) = 0xF0
        packet.push(0xF0);
        // Version
        packet.extend_from_slice(&0x0000_0001u32.to_be_bytes());
        // DCID Len = 4
        packet.push(4);
        // DCID
        packet.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);
        // SCID Len = 4
        packet.push(4);
        // SCID
        packet.extend_from_slice(&[0x05, 0x06, 0x07, 0x08]);
        // Token
        packet.extend_from_slice(b"retry-token-data");
        // Integrity Tag (16 bytes)
        packet.extend_from_slice(&[0x00; 16]);

        let info = RetryInfo::parse(&packet).expect("parse should succeed");
        assert_eq!(info.version, 0x0000_0001);
        assert_eq!(info.dst_cid, vec![0x01, 0x02, 0x03, 0x04]);
        assert_eq!(info.src_cid, vec![0x05, 0x06, 0x07, 0x08]);
        assert_eq!(info.token, b"retry-token-data".to_vec());
    }

    #[test]
    fn test_retry_packet_parse_invalid() {
        // Too short
        assert!(RetryInfo::parse(&[0xF0, 0x00, 0x00, 0x00]).is_err());
        // Not a Retry (Initial instead: type = 0b00)
        let mut initial = vec![0x80 | 0x40]; // Long header, Fixed bit, type 0
        initial.extend_from_slice(&0x0000_0001u32.to_be_bytes());
        initial.push(0);
        assert!(RetryInfo::parse(&initial).is_err());
    }
}
