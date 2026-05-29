/// Topology prober for firewall hop-count detection.
///
/// Uses incremental-TTL ICMP echo requests (traceroute-style) to find the
/// number of hops to the first middlebox that silently drops expired packets.
///
/// # Platform
/// Requires Linux (`CAP_NET_RAW` + `CAP_NET_ADMIN`) because it uses
/// `RawChannel` with `AF_PACKET` RX.
use anyhow::Result;
use std::net::Ipv4Addr;
use std::time::Duration;

use crate::core::net_evasion::packet_forge::IpBuilder;
use crate::core::net_evasion::raw_socket::RawChannel;

/// Probe the network path to `target` and return the hop count to the
/// last responsive hop before a silent drop (typically a firewall).
///
/// Sends ICMP echo requests with TTL = 1, 2, 3, ... and waits for
/// ICMP Time Exceeded responses. If no response within `timeout_per_hop`,
/// assumes a firewall dropped the probe and returns the previous TTL.
pub async fn traceroute_to_firewall(
    channel: RawChannel,
    target: Ipv4Addr,
    max_hops: u8,
) -> Result<u8> {
    let timeout = Duration::from_millis(500);
    let local_ip = Ipv4Addr::new(0, 0, 0, 0);

    for ttl in 1..=max_hops {
        let icmp = build_icmp_echo(ttl as u16);
        let ip = IpBuilder::new(local_ip, target, 1) // 1 = ICMP
            .with_ttl(ttl)
            .with_payload_len(icmp.len() as u16)
            .build();
        let mut packet = ip;
        packet.extend_from_slice(&icmp);

        channel.send_batch(&[packet]).await?;

        // Wait for ICMP Time Exceeded
        match channel.recv_timeout(timeout).await? {
            Some(buf) if buf.len() > 14 => {
                // AF_PACKET includes 14-byte Ethernet header
                let ip_pkt = &buf[14..];
                if ip_pkt.len() < 20 {
                    continue;
                }
                // Check protocol = ICMP (1)
                if ip_pkt[9] != 1 {
                    continue;
                }
                let ip_hdr_len = ((ip_pkt[0] & 0x0F) * 4) as usize;
                if ip_pkt.len() < ip_hdr_len + 8 {
                    continue;
                }
                let icmp_pkt = &ip_pkt[ip_hdr_len..];
                // ICMP Time Exceeded = type 11
                if icmp_pkt[0] == 11 {
                    // Continue to next TTL
                    continue;
                }
                // ICMP Echo Reply = type 0 → target reached
                if icmp_pkt[0] == 0 {
                    return Ok(ttl);
                }
            }
            _ => {
                // Timeout or short packet → firewall silently dropped
                return Ok(ttl.saturating_sub(1).max(1));
            }
        }
    }

    // Reached max_hops without finding a silent drop
    Ok(max_hops)
}

/// Build a minimal ICMP echo request packet.
fn build_icmp_echo(seq: u16) -> Vec<u8> {
    let mut pkt = vec![0u8; 8 + 8]; // ICMP header + 8 bytes payload
    pkt[0] = 8; // Type: Echo Request
    pkt[1] = 0; // Code: 0
    // Identifier (2 bytes) + Sequence (2 bytes)
    pkt[4..6].copy_from_slice(&0xBEEF_u16.to_be_bytes());
    pkt[6..8].copy_from_slice(&seq.to_be_bytes());
    // Payload
    pkt[8..].copy_from_slice(b"OSINTULT");

    // Compute checksum
    let checksum = internet_checksum(&pkt);
    pkt[2..4].copy_from_slice(&checksum.to_be_bytes());
    pkt
}

/// Compute Internet checksum (RFC 1071).
fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_icmp_echo() {
        let pkt = build_icmp_echo(1);
        assert_eq!(pkt[0], 8); // Echo Request
        assert_eq!(pkt[1], 0);
        assert_eq!(pkt.len(), 16);
        // Checksum should be valid
        let sum = internet_checksum(&pkt);
        assert_eq!(sum, 0);
    }

    #[test]
    fn test_internet_checksum() {
        // RFC 1071 example
        let data = [0x00, 0x01, 0xF2, 0x03, 0xF4, 0xF5, 0xF6, 0xF7];
        let cs = internet_checksum(&data);
        assert_eq!(cs, 0x220D);
    }
}
