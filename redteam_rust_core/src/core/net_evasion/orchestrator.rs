use crate::core::net_evasion::fragment_assembler::FragmentAssembler;
use crate::core::net_evasion::fragment_prober::FragmentProber;
use crate::core::net_evasion::raw_socket::RawChannel;
use crate::core::net_evasion::{EvasionResult, NetEvasionStrategy, OverlapStrategy, ReassemblyPolicy};
use anyhow::Result;
use std::net::Ipv4Addr;

/// Minimal orchestrator stub for Sprint 2.
///
/// Coordinates the fragment prober and assembler for L3 evasion attacks.
/// Expanded in Sprint 6 with full strategy selection via Thompson Sampling.
pub struct NetEvasionOrchestrator {
    channel: RawChannel,
    policy: ReassemblyPolicy,
    local_ip: Ipv4Addr,
}

impl NetEvasionOrchestrator {
    pub fn new(channel: RawChannel) -> Result<Self> {
        #[cfg(target_os = "linux")]
        let local_ip = crate::core::net_evasion::tcp_session::pick_local_ip()?;
        #[cfg(not(target_os = "linux"))]
        let local_ip = Ipv4Addr::new(127, 0, 0, 1);

        Ok(Self {
            channel,
            policy: ReassemblyPolicy::Unknown,
            local_ip,
        })
    }

    /// Probes the target to determine its fragment reassembly policy.
    pub async fn probe_target(&mut self, target: Ipv4Addr) -> Result<ReassemblyPolicy> {
        let prober = FragmentProber::new(self.channel.clone());
        self.policy = prober.probe(target).await?;
        Ok(self.policy)
    }

    /// Performs a fragmentation evasion attack against `target`.
    ///
    /// `payload`: L4 header + data to fragment and deliver.
    /// `strategy`: Fragmentation strategy (Tiny, PoisonFirst, PoisonLast).
    pub async fn fragment_attack(
        &self,
        target: Ipv4Addr,
        payload: &[u8],
        strategy: OverlapStrategy,
    ) -> Result<EvasionResult> {
        let ip_template = crate::core::net_evasion::packet_forge::IpBuilder::new(
            self.local_ip,
            target,
            6, // TCP
        );

        let fragments = FragmentAssembler::split_packet(&ip_template, payload, 1500, strategy);
        let packets_sent = fragments.len() as u32;

        let start = std::time::Instant::now();
        self.channel.send_batch(&fragments).await?;
        let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

        // TODO: Response detection in Sprint 6 ( correlate with recv_timeout )
        Ok(EvasionResult {
            strategy_used: match strategy {
                OverlapStrategy::Tiny => NetEvasionStrategy::TinyFragments,
                OverlapStrategy::PoisonFirst | OverlapStrategy::PoisonLast => {
                    NetEvasionStrategy::OverlappingFragments
                }
            },
            success: true,
            packets_sent,
            response_received: false,
            latency_ms,
        })
    }

    /// Performs a TCP L4 evasion attack against `target`.
    #[cfg(target_os = "linux")]
    pub async fn tcp_evasion_attack(
        &self,
        target: std::net::SocketAddrV4,
        payload: &[u8],
        strategy: NetEvasionStrategy,
    ) -> Result<EvasionResult> {
        use crate::core::net_evasion::tcp_evasion::TcpEvasionStrategy;
        use crate::core::net_evasion::tcp_fast_open::TcpFastOpenBypass;
        use crate::core::net_evasion::tcp_micro_segmentation::TcpMicroSegmentation;
        use crate::core::net_evasion::tcp_state_desync::TcpStateDesync;
        use crate::core::net_evasion::tcp_urgent_abuse::TcpUrgentAbuse;
        use crate::core::net_evasion::tcp_zero_window::TcpZeroWindowDesync;

        match strategy {
            NetEvasionStrategy::TcpMicroSegmentation => {
                TcpMicroSegmentation.execute(self.channel.clone(), self.local_ip, target, payload).await
            }
            NetEvasionStrategy::TcpStateDesync => {
                TcpStateDesync.execute(self.channel.clone(), self.local_ip, target, payload).await
            }
            NetEvasionStrategy::UrgentPointerAbuse => {
                TcpUrgentAbuse.execute(self.channel.clone(), self.local_ip, target, payload).await
            }
            NetEvasionStrategy::ZeroWindowDesync => {
                TcpZeroWindowDesync.execute(self.channel.clone(), self.local_ip, target, payload).await
            }
            NetEvasionStrategy::TcpFastOpenBypass => {
                TcpFastOpenBypass.execute(self.channel.clone(), self.local_ip, target, payload).await
            }
            _ => Err(anyhow::anyhow!("Not a TCP evasion strategy")),
        }
    }

    /// Returns the last known reassembly policy.
    pub fn policy(&self) -> ReassemblyPolicy {
        self.policy
    }
}
