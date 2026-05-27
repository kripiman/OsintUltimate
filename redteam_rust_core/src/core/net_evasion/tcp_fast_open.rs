//! Sprint 3 TFO: SYN + invalid_cookie + data.
//! Server rejects the invalid cookie → falls back to normal handshake.
//! Data is NOT delivered as TFO payload. This module is a packet construction scaffold.
//! Real cookie cache + actual bypass deferred to Sprint 7+.

#[cfg(target_os = "linux")]
use crate::core::net_evasion::packet_forge::{IpBuilder, TcpBuilder, TCP_SYN};
#[cfg(target_os = "linux")]
use crate::core::net_evasion::raw_socket::RawChannel;
#[cfg(target_os = "linux")]
use crate::core::net_evasion::tcp_evasion::TcpEvasionStrategy;
#[cfg(target_os = "linux")]
use crate::core::net_evasion::{EvasionResult, NetEvasionStrategy};
#[cfg(target_os = "linux")]
use anyhow::Result;
#[cfg(target_os = "linux")]
use std::net::{Ipv4Addr, SocketAddrV4};

#[cfg(target_os = "linux")]
pub struct TcpFastOpenBypass;

#[cfg(target_os = "linux")]
#[async_trait::async_trait]
impl TcpEvasionStrategy for TcpFastOpenBypass {
    fn strategy(&self) -> NetEvasionStrategy {
        NetEvasionStrategy::TcpFastOpenBypass
    }

    async fn execute(
        &self,
        channel: RawChannel,
        local_ip: Ipv4Addr,
        target: SocketAddrV4,
        payload: &[u8],
    ) -> Result<EvasionResult> {
        let src_port = rand::random::<u16>() % (32768 - 1025) + 1025;

        // SYN + TFO cookie + data
        let tcp = TcpBuilder::new(src_port, target.port())
            .with_flags(TCP_SYN)
            .with_options(&[
                34, 10, // TFO option kind=34, len=10
                0, 0, 0, 0, // cookie placeholder (8 bytes)
                0, 0, 0, 0,
            ]);

        let tcp_hdr = tcp.build();
        let checksum = tcp.calculate_checksum(local_ip, *target.ip(), &tcp_hdr, payload);
        let mut final_tcp = tcp_hdr;
        final_tcp[16..18].copy_from_slice(&checksum.to_be_bytes());

        let ip = IpBuilder::new(local_ip, *target.ip(), 6)
            .with_payload_len((final_tcp.len() + payload.len()) as u16)
            .build();

        let mut packet = ip;
        packet.extend_from_slice(&final_tcp);
        packet.extend_from_slice(payload);

        channel.send_batch(&[packet]).await?;

        // Sprint 3: invalid cookie → server rejects → fallback to normal handshake.
        // Data NOT delivered. success=false per plan.
        Ok(EvasionResult {
            strategy_used: NetEvasionStrategy::TcpFastOpenBypass,
            success: false,
            packets_sent: 1,
            response_received: false,
            latency_ms: 0.0,
        })
    }
}
