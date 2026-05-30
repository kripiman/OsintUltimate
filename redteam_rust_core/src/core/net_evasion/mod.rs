pub mod packet_forge;
#[cfg(target_os = "linux")]
pub mod raw_socket;
pub mod l2_parser;
pub mod fragment_assembler;
pub mod fragment_prober;
pub mod ttl_insertion;
pub mod orchestrator;
#[cfg(target_os = "linux")]
pub mod tcp_session;
#[cfg(target_os = "linux")]
pub mod tcp_evasion;
#[cfg(target_os = "linux")]
pub mod tcp_micro_segmentation;
#[cfg(target_os = "linux")]
pub mod tcp_state_desync;
#[cfg(target_os = "linux")]
pub mod tcp_urgent_abuse;
#[cfg(target_os = "linux")]
pub mod tcp_zero_window;
#[cfg(target_os = "linux")]
pub mod tcp_fast_open;
pub mod ja4_spoofer;
pub mod tls_raw_forge;
pub mod ja4_http_client;
#[cfg(target_os = "linux")]
pub mod af_xdp_channel;
pub mod quic_forge;
pub mod quinn_client;
pub mod http3_client;
pub mod quic_evasion;
pub mod doh3_client;
pub mod domain_front;
pub mod ech_client;
pub mod ech_dns_fetcher;
pub mod tls13_0rtt;
#[cfg(target_os = "linux")]
pub mod topology_prober;

use serde::{Deserialize, Serialize};

/// Determines how the target host reassembles overlapping IP fragments.
/// Required for L3 fragmentation attacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReassemblyPolicy {
    /// Windows policy: The last overlapping fragment received overwrites earlier ones.
    WindowsLast,
    /// Linux policy: The first fragment received is kept, later overlaps are discarded.
    LinuxFirst,
    /// BSD policy: Similar to LinuxFirst, but with different URG pointer handling.
    BsdFirst,
    /// Unknown: Probing is required to determine the policy.
    Unknown,
}

/// Strategy for overlapping fragment payload placement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OverlapStrategy {
    /// Poison data placed in the FIRST fragment. Attacks Last-Wins targets (Windows).
    /// Real payload is in the overlapping LAST fragment.
    PoisonFirst,
    /// Poison data placed in the LAST fragment. Attacks First-Wins targets (Linux/BSD).
    /// Real payload is in the FIRST fragment.
    PoisonLast,
    /// Each non-final fragment carries exactly 8 bytes payload (minimum representable unit per RFC 791).
    /// Forces middlebox to reassemble at maximum granularity.
    Tiny,
}

/// The specific L3/L4 evasion strategy employed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetEvasionStrategy {
    // L3 Evasion
    OverlappingFragments,
    TinyFragments,
    TtlInsertion,
    IpSourceRoute,
    
    // L4 Evasion
    TcpMicroSegmentation,
    TcpStateDesync,
    UrgentPointerAbuse,
    ZeroWindowDesync,
    TcpFastOpenBypass,
    
    // Tunneling
    IcmpTunnel,
    DnsTunnel,
    GreTunnel,
    QuicTunnel,
    
    // L7 / TLS Evasion
    Ja4Spoofing,
    QuicProbe,
    QuicFullHandshake,
    Http3Request,
    QuicZeroRtt,
    QuicRetryProbe,
    DomainFronting,
    EchConnect,
    EchDnsFetch,
    Tls13ZeroRtt,
    
    // Meta / FW Stress
    #[cfg(feature = "sovereign")]
    StateTableExhaustion,
    #[cfg(feature = "sovereign")]
    CpuExhaustion,
}

/// The outcome of an evasion attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvasionResult {
    pub strategy_used: NetEvasionStrategy,
    pub success: bool,
    pub packets_sent: u32,
    pub response_received: bool,
    pub latency_ms: f64,
}
