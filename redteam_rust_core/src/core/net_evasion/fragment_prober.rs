use crate::core::net_evasion::l2_parser::{EthernetFrame, ParseResult};
use crate::core::net_evasion::packet_forge::{IcmpBuilder, IpBuilder};
use crate::core::net_evasion::raw_socket::RawChannel;
use crate::core::net_evasion::ReassemblyPolicy;
use anyhow::{Context, Result};
use std::net::Ipv4Addr;
use std::time::Duration;

/// Probes the target's IP fragment reassembly policy.
///
/// **Does NOT use `FragmentAssembler`.** The prober requires precise control
/// over overlap bytes (known patterns 0xAA / 0xBB) for detection.
/// `FragmentAssembler` generates random decoy bytes for evasion;
/// this is unsuitable for probing.
///
/// Detection method: ICMP Echo Request/Reply with overlapping data payload.
///
/// **Modern Linux limitation:** Linux 5.0+ `nf_defrag_ipv4` drops overlapping
/// fragments before reassembly. Prober returns `Unknown` on such targets.
pub struct FragmentProber {
    channel: RawChannel,
}

impl FragmentProber {
    pub fn new(channel: RawChannel) -> Self {
        Self { channel }
    }

    /// Probes `target` to determine its reassembly policy.
    ///
    /// Returns:
    /// - `LinuxFirst`  → first-wins (overlap bytes == 0xAA)
    /// - `WindowsLast` → last-wins  (overlap bytes == 0xBB)
    /// - `Unknown`     → no reply, time exceeded, or modern Linux drop
    pub async fn probe(&self, target: Ipv4Addr) -> Result<ReassemblyPolicy> {
        let src_ip = Self::pick_source_ip()?;
        let overlap_size = 8usize;
        let icmp_data_len = 16usize; // 8-byte ICMP header + 8-byte overlap data

        // Both fragments MUST share the same ip_id for kernel reassembly.
        let probe_ip_id: u16 = rand::random();

        // --- Build Fragment A: poison in data region ---
        let frag_a_payload = Self::build_icmp_echo_payload(0xAA, overlap_size, icmp_data_len);
        let frag_a = IpBuilder::new(src_ip, target, 1) // 1 = ICMP
            .with_identification(probe_ip_id)
            .with_fragmentation(0x01, 0) // MF=1, offset=0
            .with_payload_len(frag_a_payload.len() as u16)
            .build();
        let mut packet_a = frag_a;
        packet_a.extend_from_slice(&frag_a_payload);

        // --- Build Fragment B: real in data region ---
        let frag_b_payload = Self::build_icmp_echo_payload(0xBB, overlap_size, icmp_data_len);
        let frag_b = IpBuilder::new(src_ip, target, 1)
            .with_identification(probe_ip_id) // SAME ip_id
            .with_fragmentation(0x00, 0) // MF=0, offset=0
            .with_payload_len(frag_b_payload.len() as u16)
            .build();
        let mut packet_b = frag_b;
        packet_b.extend_from_slice(&frag_b_payload);

        // Send both fragments
        self.channel
            .send_batch(&[packet_a, packet_b])
            .await
            .context("send_batch failed for probe fragments")?;

        // Wait for reply
        let deadline = Duration::from_millis(2000);
        let start = std::time::Instant::now();

        while start.elapsed() < deadline {
            let timeout = std::cmp::min(
                Duration::from_millis(200),
                deadline.saturating_sub(start.elapsed()),
            );

            match self.channel.recv_timeout(timeout).await? {
                None => continue,
                Some(buf) => {
                    let eth = match EthernetFrame::parse(&buf) {
                        ParseResult::Ipv4(frame) => frame,
                        ParseResult::OtherProto(_) => continue,
                        ParseResult::Malformed => continue,
                    };

                    let ip_payload = eth.payload;
                    if ip_payload.len() < 20 {
                        continue;
                    }

                    // Parse IP header
                    let proto = ip_payload[9];
                    let src = Ipv4Addr::new(ip_payload[12], ip_payload[13], ip_payload[14], ip_payload[15]);
                    let _dst = Ipv4Addr::new(ip_payload[16], ip_payload[17], ip_payload[18], ip_payload[19]);

                    // Must be ICMP from target back to us
                    if proto != 1 || src != target {
                        continue;
                    }

                    let ip_hdr_len = ((ip_payload[0] & 0x0F) * 4) as usize;
                    if ip_payload.len() < ip_hdr_len + 8 {
                        continue;
                    }

                    let icmp = &ip_payload[ip_hdr_len..];
                    let icmp_type = icmp[0];
                    let icmp_code = icmp[1];

                    // ICMP Time Exceeded (type=11, code=1) → fragment reassembly failed
                    if icmp_type == 11 && icmp_code == 1 {
                        return Ok(ReassemblyPolicy::Unknown);
                    }

                    // ICMP Echo Reply (type=0, code=0)
                    if icmp_type == 0 && icmp_code == 0 {
                        // Read reply data bytes 8-15 (the overlap zone), NOT bytes 0-7 (ICMP header)
                        let icmp_data = &icmp[8..];
                        if icmp_data.len() < overlap_size {
                            continue;
                        }
                        let overlap_bytes = &icmp_data[..overlap_size];

                        if overlap_bytes.iter().all(|&b| b == 0xAA) {
                            return Ok(ReassemblyPolicy::LinuxFirst);
                        }
                        if overlap_bytes.iter().all(|&b| b == 0xBB) {
                            return Ok(ReassemblyPolicy::WindowsLast);
                        }
                    }
                }
            }
        }

        Ok(ReassemblyPolicy::Unknown)
    }

    /// Build ICMP Echo Request payload with known overlap pattern.
    ///
    /// Structure:
    /// ```text
    /// bytes 0-7:  ICMP header (type=8, code=0, checksum, id, seq)
    /// bytes 8-15: ICMP data = [pattern; 8]  ← overlap zone
    /// ```
    fn build_icmp_echo_payload(pattern: u8, _overlap_size: usize, total_len: usize) -> Vec<u8> {
        let mut icmp = IcmpBuilder::new(8, 0).build(); // type=8, code=0 = Echo Request
        // Pad data to total_len - 8 (header size)
        let data_len = total_len.saturating_sub(8);
        let data = vec![pattern; data_len];
        icmp.extend_from_slice(&data);

        // Calculate checksum over header + data
        let checksum = IcmpBuilder::new(8, 0).calculate_checksum(&icmp, &[]);
        icmp[2..4].copy_from_slice(&checksum.to_be_bytes());

        icmp
    }

    fn pick_source_ip() -> Result<Ipv4Addr> {
        // TODO: Interface IP enumeration.
        Ok(Ipv4Addr::new(0, 0, 0, 0))
    }
}
