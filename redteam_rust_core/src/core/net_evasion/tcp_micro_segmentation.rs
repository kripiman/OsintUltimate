#[cfg(target_os = "linux")]
use crate::core::net_evasion::packet_forge::{TCP_ACK, TCP_PSH};
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
pub struct TcpMicroSegmentation;

#[cfg(target_os = "linux")]
#[async_trait::async_trait]
impl TcpEvasionStrategy for TcpMicroSegmentation {
    fn strategy(&self) -> NetEvasionStrategy {
        NetEvasionStrategy::TcpMicroSegmentation
    }

    async fn execute(
        &self,
        channel: RawChannel,
        local_ip: Ipv4Addr,
        target: SocketAddrV4,
        payload: &[u8],
    ) -> Result<EvasionResult> {
        let mut session = TcpSession::connect(channel, local_ip, target).await?;

        let start = std::time::Instant::now();
        let packets_sent = payload.len() as u32;

        // Send payload one byte per PSH|ACK segment
        for byte in payload {
            session
                .send_segment(TCP_PSH | TCP_ACK, None, &[*byte])
                .await?;
        }

        let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

        Ok(EvasionResult {
            strategy_used: NetEvasionStrategy::TcpMicroSegmentation,
            success: true,
            packets_sent,
            response_received: false,
            latency_ms,
        })
    }
}
