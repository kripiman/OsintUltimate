use crate::core::net_evasion::packet_forge::IpBuilder;
use crate::core::net_evasion::OverlapStrategy;

/// RFC 791 compliant IPv4 fragment assembler.
///
/// Generates complete IP datagrams (IP header + fragment payload) ready
/// for transmission via `RawChannel::send_batch()`.
pub struct FragmentAssembler;

impl FragmentAssembler {
    /// Splits `payload` (L4 header + data) into RFC 791 compliant IPv4 fragments.
    /// Each returned `Vec<u8>` is a **complete IP datagram**.
    ///
    /// `ip_template` provides src_ip, dst_ip, protocol, ttl, tos, identification.
    /// `mtu` is the maximum total size per fragment (including 20-byte IP header).
    /// `overlap_strategy` selects Tiny, PoisonFirst, or PoisonLast behavior.
    ///
    /// For PoisonFirst/PoisonLast: decoy bytes are generated internally (random,
    /// same length as overlap region). Caller provides real payload only.
    pub fn split_packet(
        ip_template: &IpBuilder,
        payload: &[u8],
        mtu: u16,
        overlap_strategy: OverlapStrategy,
    ) -> Vec<Vec<u8>> {
        let ip_header_len = 20u16;
        let max_frag_payload = mtu.saturating_sub(ip_header_len);

        // For non-final fragments, payload must be a multiple of 8 bytes.
        let frag_size = match overlap_strategy {
            OverlapStrategy::Tiny => 8,
            _ => (max_frag_payload / 8) * 8,
        };
        let frag_size = std::cmp::max(frag_size, 8) as usize;

        match overlap_strategy {
            OverlapStrategy::Tiny => Self::split_tiny(ip_template, payload, frag_size),
            OverlapStrategy::PoisonFirst => {
                Self::split_overlap(ip_template, payload, frag_size, true)
            }
            OverlapStrategy::PoisonLast => {
                Self::split_overlap(ip_template, payload, frag_size, false)
            }
        }
    }

    /// Build a single fragment: IP header + payload.
    fn build_fragment(
        ip_template: &IpBuilder,
        offset_8byte: u16,
        mf: bool,
        payload: &[u8],
    ) -> Vec<u8> {
        let flags = if mf { 0x01 } else { 0 }; // MF bit → shifted to 0x2000 by IpBuilder
        let ip = ip_template
            .clone()
            .with_fragmentation(flags, offset_8byte)
            .with_payload_len(payload.len() as u16);
        let mut packet = ip.build();
        packet.extend_from_slice(payload);
        packet
    }

    fn split_tiny(ip_template: &IpBuilder, payload: &[u8], frag_size: usize) -> Vec<Vec<u8>> {
        let mut fragments = Vec::new();
        let mut offset = 0usize;

        while offset < payload.len() {
            let end = std::cmp::min(offset + frag_size, payload.len());
            let is_last = end >= payload.len();
            let frag_payload = &payload[offset..end];
            let frag_offset_8byte = (offset / 8) as u16;
            fragments.push(Self::build_fragment(
                ip_template,
                frag_offset_8byte,
                !is_last,
                frag_payload,
            ));
            offset = end;
        }

        // Edge case: empty payload → single final fragment with 0 bytes.
        if fragments.is_empty() {
            fragments.push(Self::build_fragment(ip_template, 0, false, &[]));
        }

        fragments
    }

    fn split_overlap(
        ip_template: &IpBuilder,
        payload: &[u8],
        frag_size: usize,
        poison_first: bool,
    ) -> Vec<Vec<u8>> {
        let mut fragments = Vec::new();
        let first_chunk = std::cmp::min(frag_size, payload.len());
        let has_more = payload.len() > first_chunk;

        // Generate random decoy bytes for the overlap region.
        let decoy: Vec<u8> = (0..first_chunk).map(|_| rand::random::<u8>()).collect();

        // Fragment A (first sent) MUST have MF=1 to force kernel reassembly,
        // even if the entire payload fits in one chunk.
        let frag_a_mf = true;
        let frag_b_mf = has_more;

        if poison_first {
            // Poison fragment sent FIRST; real fragment sent LAST.
            // Target: Last-Wins (Windows) → real wins.
            let mut poison_frag = payload[..first_chunk].to_vec();
            poison_frag.copy_from_slice(&decoy);
            fragments.push(Self::build_fragment(
                ip_template, 0, frag_a_mf, &poison_frag,
            ));
            fragments.push(Self::build_fragment(
                ip_template, 0, frag_b_mf, &payload[..first_chunk],
            ));
        } else {
            // Real fragment sent FIRST; poison fragment sent LAST.
            // Target: First-Wins (Linux/BSD) → real wins.
            fragments.push(Self::build_fragment(
                ip_template, 0, frag_a_mf, &payload[..first_chunk],
            ));
            let mut poison_frag = payload[..first_chunk].to_vec();
            poison_frag.copy_from_slice(&decoy);
            fragments.push(Self::build_fragment(
                ip_template, 0, frag_b_mf, &poison_frag,
            ));
        }

        // Remaining non-overlapping fragments.
        let mut offset = first_chunk;
        while offset < payload.len() {
            let end = std::cmp::min(offset + frag_size, payload.len());
            let is_last = end >= payload.len();
            let frag_payload = &payload[offset..end];
            let frag_offset_8byte = (offset / 8) as u16;
            fragments.push(Self::build_fragment(
                ip_template,
                frag_offset_8byte,
                !is_last,
                frag_payload,
            ));
            offset = end;
        }

        fragments
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::net_evasion::packet_forge::IpBuilder;
    use std::net::Ipv4Addr;

    #[test]
    fn test_tiny_fragments() {
        let ip = IpBuilder::new(
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 1, 2),
            6,
        );
        let payload = vec![0u8; 24]; // 24 bytes → 3 fragments of 8
        let frags = FragmentAssembler::split_packet(&ip, &payload, 1500, OverlapStrategy::Tiny);

        assert_eq!(frags.len(), 3);
        for (i, frag) in frags.iter().enumerate() {
            // IP header + payload
            assert_eq!(frag.len(), 20 + 8);
            // Version 4, IHL 5
            assert_eq!(frag[0], 0x45);
            // Check MF on first two, clear on last
            let flags_offset = u16::from_be_bytes([frag[6], frag[7]]);
            let mf = (flags_offset & 0x2000) != 0;
            let offset = (flags_offset & 0x1FFF) as usize;
            assert_eq!(offset, i); // 8 bytes = 1 unit
            assert_eq!(mf, i < 2);
        }
    }

    #[test]
    fn test_poison_first_overlap() {
        let ip = IpBuilder::new(
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 1, 2),
            6,
        );
        let payload = vec![0xAB; 32];
        let frags = FragmentAssembler::split_packet(
            &ip,
            &payload,
            1500,
            OverlapStrategy::PoisonFirst,
        );

        // At least 2 fragments at offset 0 (overlap)
        assert!(frags.len() >= 2);
        let frag0_offset = u16::from_be_bytes([frags[0][6], frags[0][7]]) & 0x1FFF;
        let frag1_offset = u16::from_be_bytes([frags[1][6], frags[1][7]]) & 0x1FFF;
        assert_eq!(frag0_offset, 0);
        assert_eq!(frag1_offset, 0);

        // First fragment (poison) should differ from second (real) in overlap region
        let frag0_payload = &frags[0][20..];
        let frag1_payload = &frags[1][20..];
        assert_eq!(frag0_payload.len(), frag1_payload.len());
        assert_ne!(frag0_payload, frag1_payload);
    }

    #[test]
    fn test_empty_payload() {
        let ip = IpBuilder::new(
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 1, 2),
            6,
        );
        let frags = FragmentAssembler::split_packet(&ip, &[], 1500, OverlapStrategy::Tiny);
        assert_eq!(frags.len(), 1);
        assert_eq!(frags[0].len(), 20); // header only
    }
}
