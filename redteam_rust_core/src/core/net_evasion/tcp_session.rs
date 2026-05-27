//! IMPORTANT: Rule cleanup must run on panic/abort.
//! Use `Drop` impl + signal-hook for SIGINT/SIGTERM to ensure
//! iptables rules are removed even on unclean exit.
//! Stale rules block legitimate RST flow.

#[cfg(target_os = "linux")]
use crate::core::net_evasion::l2_parser::{EthernetFrame, ParseResult};
#[cfg(target_os = "linux")]
use crate::core::net_evasion::packet_forge::{IpBuilder, TcpBuilder, TCP_ACK, TCP_SYN, TCP_FIN};
#[cfg(target_os = "linux")]
use crate::core::net_evasion::raw_socket::RawChannel;
#[cfg(target_os = "linux")]
use anyhow::{Context, Result};
#[cfg(target_os = "linux")]
use std::net::{Ipv4Addr, SocketAddrV4};
#[cfg(target_os = "linux")]
use std::process::Command;
#[cfg(target_os = "linux")]
use std::sync::{Mutex, Once};
#[cfg(target_os = "linux")]
use std::time::Duration;
#[cfg(target_os = "linux")]
use tracing::{debug, warn};

#[cfg(target_os = "linux")]
static ACTIVE_RULES: Mutex<Vec<(Ipv4Addr, Ipv4Addr, u16)>> = Mutex::new(Vec::new());
#[cfg(target_os = "linux")]
static SIGNAL_REGISTERED: Once = Once::new();

#[cfg(target_os = "linux")]
fn register_signal_handler() {
    SIGNAL_REGISTERED.call_once(|| {
        let mut signals = signal_hook::iterator::Signals::new([
            signal_hook::consts::SIGINT,
            signal_hook::consts::SIGTERM,
        ])
        .expect("Failed to register signal handler");

        std::thread::spawn(move || {
            // Handle first signal and exit
            if signals.forever().next().is_some() {
                if let Ok(rules) = ACTIVE_RULES.lock() {
                    for (local_ip, remote_ip, local_port) in rules.iter() {
                        let _ = TcpSession::remove_iptables_rst_drop(*local_ip, *remote_ip, *local_port);
                    }
                }
                std::process::exit(0);
            }
        });
    });
}

/// Picks the first non-loopback IPv4 address from local interfaces.
#[cfg(target_os = "linux")]
pub fn pick_local_ip() -> Result<Ipv4Addr> {
    unsafe {
        let mut ifaddrs: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifaddrs) != 0 {
            return Err(anyhow::anyhow!("getifaddrs failed"));
        }

        let mut current = ifaddrs;
        while !current.is_null() {
            let ifa = &*current;
            if !ifa.ifa_addr.is_null() && (*ifa.ifa_addr).sa_family as i32 == libc::AF_INET {
                let addr = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                let ip_bytes = addr.sin_addr.s_addr.to_be_bytes();
                let ip = Ipv4Addr::new(ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
                if !ip.is_loopback() {
                    libc::freeifaddrs(ifaddrs);
                    return Ok(ip);
                }
            }
            current = ifa.ifa_next;
        }

        libc::freeifaddrs(ifaddrs);
        Err(anyhow::anyhow!(
            "No non-loopback IPv4 interface found"
        ))
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    SynSent,
    Established,
}

#[cfg(target_os = "linux")]
pub struct TcpSession {
    pub local_ip: Ipv4Addr,
    pub local_port: u16,
    pub remote_ip: Ipv4Addr,
    pub remote_port: u16,
    pub local_seq: u32,
    pub remote_seq: u32,
    pub remote_ack: u32,
    pub state: TcpState,
    pub channel: RawChannel,
    iptables_applied: bool,
}

#[cfg(target_os = "linux")]
impl TcpSession {
    /// Creates session with local IP + auto-managed iptables RST DROP rule.
    /// Rule added on connect, removed on Drop.
    /// Performs 3-way handshake via RawChannel.
    pub async fn connect(
        channel: RawChannel,
        local_ip: Ipv4Addr,
        remote: SocketAddrV4,
    ) -> Result<Self> {
        register_signal_handler();

        let local_port = rand::random::<u16>() % (32768 - 1025) + 1025;

        // Add iptables rule to suppress kernel RST
        Self::add_iptables_rst_drop(local_ip, *remote.ip(), local_port)
            .context("Failed to add iptables RST DROP rule")?;

        // Track for signal-handler cleanup
        if let Ok(mut rules) = ACTIVE_RULES.lock() {
            rules.push((local_ip, *remote.ip(), local_port));
        }

        let local_seq: u32 = rand::random();

        // --- SYN ---
        let syn_tcp = TcpBuilder::new(local_port, remote.port())
            .with_seq(local_seq)
            .with_flags(TCP_SYN);
        let syn_pkt = Self::build_ip_packet(local_ip, *remote.ip(), &syn_tcp, &[])?;
        channel.send_batch(&[syn_pkt]).await?;

        debug!(
            "SYN sent: {}:{} -> {}:{}, seq={}",
            local_ip,
            local_port,
            remote.ip(),
            remote.port(),
            local_seq
        );

        // --- Wait for SYN-ACK ---
        let (remote_seq, remote_ack) = Self::recv_synack(&channel, remote, local_port)
            .await
            .context("Failed to receive SYN-ACK")?;

        debug!(
            "SYN-ACK received: remote_seq={}, remote_ack={}",
            remote_seq,
            remote_ack
        );

        // --- ACK ---
        let ack_tcp = TcpBuilder::new(local_port, remote.port())
            .with_seq(local_seq.wrapping_add(1))
            .with_ack(remote_seq.wrapping_add(1))
            .with_flags(TCP_ACK);
        let ack_pkt = Self::build_ip_packet(local_ip, *remote.ip(), &ack_tcp, &[])?;
        channel.send_batch(&[ack_pkt]).await?;

        Ok(Self {
            local_ip,
            local_port,
            remote_ip: *remote.ip(),
            remote_port: remote.port(),
            local_seq: local_seq.wrapping_add(1),
            remote_seq: remote_seq.wrapping_add(1),
            remote_ack,
            state: TcpState::Established,
            channel,
            iptables_applied: true,
        })
    }

    /// Sends a TCP segment. `window`: None = 65535, Some(0) = zero window.
    /// Auto-advances local_seq: SYN/FIN each consume 1; data consumes len().
    pub async fn send_segment(
        &mut self,
        flags: u8,
        window: Option<u16>,
        payload: &[u8],
    ) -> Result<()> {
        let mut tcp = TcpBuilder::new(self.local_port, self.remote_port)
            .with_seq(self.local_seq)
            .with_ack(self.remote_seq)
            .with_flags(flags);

        if let Some(w) = window {
            tcp = tcp.with_window(w);
        }

        let pkt = Self::build_ip_packet(self.local_ip, self.remote_ip, &tcp, payload)?;
        self.channel.send_batch(&[pkt]).await?;

        // SEQ advancement
        let mut seq_consumed = payload.len() as u32;
        if flags & TCP_SYN != 0 {
            seq_consumed = seq_consumed.wrapping_add(1);
        }
        if flags & TCP_FIN != 0 {
            seq_consumed = seq_consumed.wrapping_add(1);
        }
        self.local_seq = self.local_seq.wrapping_add(seq_consumed);

        Ok(())
    }

    /// Receives next segment matching this session (filtered by src/dst port).
    pub async fn recv_segment(&self, timeout: Duration) -> Result<Option<Vec<u8>>> {
        let deadline = std::time::Instant::now() + timeout;

        while std::time::Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                break;
            }

            match self.channel.recv_timeout(remaining).await? {
                None => continue,
                Some(buf) => {
                    let eth = match EthernetFrame::parse(&buf) {
                        ParseResult::Ipv4(frame) => frame,
                        _ => continue,
                    };

                    let ip_payload = eth.payload;
                    if ip_payload.len() < 20 {
                        continue;
                    }

                    // IP header parsing
                    let ip_hdr_len = ((ip_payload[0] & 0x0F) * 4) as usize;
                    if ip_payload.len() < ip_hdr_len + 20 {
                        continue;
                    }

                    let proto = ip_payload[9];
                    let src_ip =
                        Ipv4Addr::new(ip_payload[12], ip_payload[13], ip_payload[14], ip_payload[15]);
                    let dst_ip =
                        Ipv4Addr::new(ip_payload[16], ip_payload[17], ip_payload[18], ip_payload[19]);

                    if proto != 6 {
                        continue; // not TCP
                    }

                    // TCP header parsing
                    let tcp_data = &ip_payload[ip_hdr_len..];
                    let src_port = u16::from_be_bytes([tcp_data[0], tcp_data[1]]);
                    let dst_port = u16::from_be_bytes([tcp_data[2], tcp_data[3]]);

                    // Match session
                    if src_ip == self.remote_ip
                        && dst_ip == self.local_ip
                        && src_port == self.remote_port
                        && dst_port == self.local_port
                    {
                        return Ok(Some(tcp_data.to_vec()));
                    }
                }
            }
        }

        Ok(None)
    }

    // --- Private helpers ---

    fn build_ip_packet(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        tcp: &TcpBuilder,
        payload: &[u8],
    ) -> Result<Vec<u8>> {
        let tcp_hdr = tcp.build();
        let checksum = tcp.calculate_checksum(src_ip, dst_ip, &tcp_hdr, payload);
        let mut final_tcp = tcp_hdr;
        final_tcp[16..18].copy_from_slice(&checksum.to_be_bytes());

        let ip = IpBuilder::new(src_ip, dst_ip, 6)
            .with_payload_len((final_tcp.len() + payload.len()) as u16)
            .build();

        let mut packet = ip;
        packet.extend_from_slice(&final_tcp);
        packet.extend_from_slice(payload);
        Ok(packet)
    }

    async fn recv_synack(
        channel: &RawChannel,
        remote: SocketAddrV4,
        local_port: u16,
    ) -> Result<(u32, u32)> {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);

        while std::time::Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                break;
            }

            match channel.recv_timeout(remaining).await? {
                None => continue,
                Some(buf) => {
                    let eth = match EthernetFrame::parse(&buf) {
                        ParseResult::Ipv4(frame) => frame,
                        _ => continue,
                    };

                    let ip_payload = eth.payload;
                    if ip_payload.len() < 20 {
                        continue;
                    }

                    let ip_hdr_len = ((ip_payload[0] & 0x0F) * 4) as usize;
                    if ip_payload.len() < ip_hdr_len + 20 {
                        continue;
                    }

                    let proto = ip_payload[9];
                    let src_ip =
                        Ipv4Addr::new(ip_payload[12], ip_payload[13], ip_payload[14], ip_payload[15]);

                    if proto != 6 || src_ip != *remote.ip() {
                        continue;
                    }

                    let tcp_data = &ip_payload[ip_hdr_len..];
                    let src_port = u16::from_be_bytes([tcp_data[0], tcp_data[1]]);
                    let dst_port = u16::from_be_bytes([tcp_data[2], tcp_data[3]]);
                    let flags = tcp_data[13];

                    if src_port == remote.port()
                        && dst_port == local_port
                        && flags & TCP_SYN != 0
                        && flags & TCP_ACK != 0
                    {
                        let seq = u32::from_be_bytes([
                            tcp_data[4], tcp_data[5], tcp_data[6], tcp_data[7],
                        ]);
                        let ack = u32::from_be_bytes([
                            tcp_data[8], tcp_data[9], tcp_data[10], tcp_data[11],
                        ]);
                        return Ok((seq, ack));
                    }
                }
            }
        }

        Err(anyhow::anyhow!(
            "Timeout waiting for SYN-ACK from {}",
            remote
        ))
    }

    fn add_iptables_rst_drop(local_ip: Ipv4Addr, remote_ip: Ipv4Addr, local_port: u16) -> Result<()> {
        // Idempotency guard: check if rule already exists
        let check = Command::new("iptables")
            .args([
                "-C", "OUTPUT",
                "-p", "tcp",
                "--tcp-flags", "RST", "RST",
                "-s", &local_ip.to_string(),
                "-d", &remote_ip.to_string(),
                "--sport", &local_port.to_string(),
                "-j", "DROP",
            ])
            .status();

        if let Ok(status) = check {
            if status.success() {
                // Rule already exists — skip add
                return Ok(());
            }
        }

        let status = Command::new("iptables")
            .args([
                "-A", "OUTPUT",
                "-p", "tcp",
                "--tcp-flags", "RST", "RST",
                "-s", &local_ip.to_string(),
                "-d", &remote_ip.to_string(),
                "--sport", &local_port.to_string(),
                "-j", "DROP",
            ])
            .status()
            .context("Failed to execute iptables -A")?;

        if !status.success() {
            return Err(anyhow::anyhow!(
                "iptables -A failed with exit code: {:?}",
                status.code()
            ));
        }
        Ok(())
    }

    pub(crate) fn remove_iptables_rst_drop(
        local_ip: Ipv4Addr,
        remote_ip: Ipv4Addr,
        local_port: u16,
    ) -> Result<()> {
        let status = Command::new("iptables")
            .args([
                "-D", "OUTPUT",
                "-p", "tcp",
                "--tcp-flags", "RST", "RST",
                "-s", &local_ip.to_string(),
                "-d", &remote_ip.to_string(),
                "--sport", &local_port.to_string(),
                "-j", "DROP",
            ])
            .status()
            .context("Failed to execute iptables -D")?;

        if !status.success() {
            warn!(
                "iptables -D exited with code {:?} — rule may already be removed",
                status.code()
            );
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Drop for TcpSession {
    fn drop(&mut self) {
        if self.iptables_applied {
            // Remove from tracked rules
            if let Ok(mut rules) = ACTIVE_RULES.lock() {
                rules.retain(|(lip, rip, lport)| {
                    !(lip == &self.local_ip && rip == &self.remote_ip && lport == &self.local_port)
                });
            }
            if let Err(e) = Self::remove_iptables_rst_drop(self.local_ip, self.remote_ip, self.local_port) {
                warn!("Failed to remove iptables RST DROP rule on drop: {}", e);
            }
        }
    }
}
