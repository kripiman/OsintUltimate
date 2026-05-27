#[cfg(target_os = "linux")]
use crate::core::net_evasion::raw_socket::RawChannel;
#[cfg(target_os = "linux")]
use crate::core::net_evasion::{EvasionResult, NetEvasionStrategy};
#[cfg(target_os = "linux")]
use anyhow::Result;
#[cfg(target_os = "linux")]
use std::net::{Ipv4Addr, SocketAddrV4};

#[cfg(target_os = "linux")]
#[async_trait::async_trait]
pub trait TcpEvasionStrategy: Send + Sync {
    fn strategy(&self) -> NetEvasionStrategy;
    async fn execute(
        &self,
        channel: RawChannel,
        local_ip: Ipv4Addr,
        target: SocketAddrV4,
        payload: &[u8],
    ) -> Result<EvasionResult>;
}
