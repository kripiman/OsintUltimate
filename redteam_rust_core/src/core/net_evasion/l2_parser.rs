/// AF_PACKET returns raw Ethernet frames. This module parses the L2 header
/// to extract the IPv4 payload.
///
/// Note: 802.1Q VLAN tags (ethertype 0x8100, +4 bytes) are NOT handled in Sprint 2.
/// Loopback testing does not encounter VLANs.

#[derive(Debug, Clone)]
pub struct EthernetFrame<'a> {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ethertype: u16, // 0x0800 = IPv4
    pub payload: &'a [u8], // IP datagram starts at offset 14
}

#[derive(Debug, Clone)]
pub enum ParseResult<'a> {
    Ipv4(EthernetFrame<'a>),
    /// Non-IPv4 frame (e.g., ARP 0x0806, IPv6 0x86DD). Caller should skip.
    OtherProto(u16),
    /// Buffer too short to contain a valid Ethernet header.
    Malformed,
}

impl<'a> EthernetFrame<'a> {
    /// Minimum valid frame: 14 bytes (6 dst + 6 src + 2 ethertype).
    ///
    /// Returns `ParseResult::Ipv4` only for ethertype 0x0800.
    /// Non-IPv4 frames return `ParseResult::OtherProto(u16)` —
    /// caller filters without catching errors.
    pub fn parse(buf: &'a [u8]) -> ParseResult<'a> {
        if buf.len() < 14 {
            return ParseResult::Malformed;
        }

        let mut dst_mac = [0u8; 6];
        let mut src_mac = [0u8; 6];
        dst_mac.copy_from_slice(&buf[0..6]);
        src_mac.copy_from_slice(&buf[6..12]);
        let ethertype = u16::from_be_bytes([buf[12], buf[13]]);

        if ethertype != 0x0800 {
            return ParseResult::OtherProto(ethertype);
        }

        ParseResult::Ipv4(EthernetFrame {
            dst_mac,
            src_mac,
            ethertype,
            payload: &buf[14..],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ipv4() {
        let mut frame = vec![0u8; 14 + 20];
        frame[12] = 0x08;
        frame[13] = 0x00;
        // IP version 4, IHL 5 at payload[0]
        frame[14] = 0x45;

        match EthernetFrame::parse(&frame) {
            ParseResult::Ipv4(eth) => {
                assert_eq!(eth.ethertype, 0x0800);
                assert_eq!(eth.payload.len(), 20);
                assert_eq!(eth.payload[0], 0x45);
            }
            other => panic!("Expected Ipv4, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_arp() {
        let mut frame = vec![0u8; 14];
        frame[12] = 0x08;
        frame[13] = 0x06;

        match EthernetFrame::parse(&frame) {
            ParseResult::OtherProto(0x0806) => {}
            other => panic!("Expected OtherProto, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_too_short() {
        let frame = vec![0u8; 10];
        match EthernetFrame::parse(&frame) {
            ParseResult::Malformed => {}
            other => panic!("Expected Malformed, got {:?}", other),
        }
    }
}
