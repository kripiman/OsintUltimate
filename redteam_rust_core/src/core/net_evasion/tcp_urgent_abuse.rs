//! **Effectiveness: legacy targets only** (Windows XP/2000, BSD 4.x).
//! Modern stacks (Linux post-2.6, Windows post-Vista, BSD post-5.x) converged on RFC 1122.
//! Retained for completeness against legacy middleboxes.

#[cfg(target_os = "linux")]
use crate::core::net_evasion::packet_forge::{TcpBuilder, TCP_ACK, TCP_PSH, TCP_URG};
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
pub struct TcpUrgentAbuse;

#[cfg(target_os = "linux")]
#[async_trait::async_trait]
impl TcpEvasionStrategy for TcpUrgentAbuse {
    fn strategy(&self) -> NetEvasionStrategy {
        NetEvasionStrategy::UrgentPointerAbuse
    }

    async fn execute(
        &self,
        channel: RawChannel,
        local_ip: Ipv4Addr,
        target: SocketAddrV4,
        payload: &[u8],
    ) -> Result<EvasionResult> {
        let start = std::time::Instant::now();
        let mut session = TcpSession::connect(channel, local_ip, target).await?;

        // RFC 793 vs RFC 1122 ambiguity:
        // - BSD/Linux (RFC 1122): urgent byte = byte AT seq + urg_ptr - 1
        // - Windows historical (RFC 793): urgent byte = byte AT seq + urg_ptr
        //
        // We send a single segment with URG flag + urg_ptr pointing to an
        // ambiguous boundary. Legacy firewalls and hosts may interpret the
        // urgent data boundary differently → payload parsing diverges.
        let ambiguity_offset = std::cmp::min(8, payload.len());

        let tcp = TcpBuilder::new(session.local_port, session.remote_port)
            .with_seq(session.local_seq)
            .with_ack(session.remote_seq)
            .with_flags(TCP_PSH | TCP_ACK | TCP_URG)
            .with_urgent_ptr(ambiguity_offset as u16)
            .with_window(65535);

        let tcp_hdr = tcp.build();
        let checksum = tcp.calculate_checksum(session.local_ip, session.remote_ip, &tcp_hdr, payload);
        let mut final_tcp = tcp_hdr;
        final_tcp[16..18].copy_from_slice(&checksum.to_be_bytes());

        let ip = crate::core::net_evasion::packet_forge::IpBuilder::new(
            session.local_ip, session.remote_ip, 6,
        )
        .with_payload_len((final_tcp.len() + payload.len()) as u16)
        .build();

        let mut packet = ip;
        packet.extend_from_slice(&final_tcp);
        packet.extend_from_slice(payload);

        session.channel.send_batch(&[packet]).await?;

        // Advance local_seq for the payload sent
        session.local_seq = session.local_seq.wrapping_add(payload.len() as u32);

        Ok(EvasionResult {
            strategy_used: NetEvasionStrategy::UrgentPointerAbuse,
            success: true,
            packets_sent: 1,
            response_received: false,
            latency_ms: start.elapsed().as_secs_f64() * 1000.0,
        })
    }
}
