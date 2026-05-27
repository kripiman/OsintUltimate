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
use std::time::Duration;

#[cfg(target_os = "linux")]
pub struct TcpZeroWindowDesync;

#[cfg(target_os = "linux")]
#[async_trait::async_trait]
impl TcpEvasionStrategy for TcpZeroWindowDesync {
    fn strategy(&self) -> NetEvasionStrategy {
        NetEvasionStrategy::ZeroWindowDesync
    }

    async fn execute(
        &self,
        channel: RawChannel,
        local_ip: Ipv4Addr,
        target: SocketAddrV4,
        payload: &[u8],
    ) -> Result<EvasionResult> {
        let start = std::time::Instant::now();

        // Step 1: Establish session
        let mut session = TcpSession::connect(channel, local_ip, target).await?;

        // Step 2: Send ONE zero-window ACK, then go completely idle.
        // Middlebox state table entries timeout after 30-120s of no traffic.
        // Continuous ACKs during idle reset the idle timer → counterproductive.
        session.send_segment(TCP_ACK, Some(0), &[]).await?;
        tokio::time::sleep(Duration::from_secs(60)).await;

        // Step 3: Send payload with normal window.
        // If middlebox timed out the state entry, payload bypasses deep inspection.
        session.send_segment(TCP_PSH | TCP_ACK, Some(65535), payload).await?;

        Ok(EvasionResult {
            strategy_used: NetEvasionStrategy::ZeroWindowDesync,
            success: true,
            packets_sent: 2, // zero-window ACK + payload
            response_received: false,
            latency_ms: start.elapsed().as_secs_f64() * 1000.0,
        })
    }
}
