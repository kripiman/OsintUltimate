#[cfg(target_os = "linux")]
use anyhow::{Context, Result};
#[cfg(target_os = "linux")]
use socket2::{Domain, Protocol, Socket, Type};
#[cfg(target_os = "linux")]
use std::{os::unix::io::AsRawFd, time::Duration};

#[cfg(target_os = "linux")]
const ETH_P_ALL: u16 = 0x0003;
#[cfg(target_os = "linux")]
const SIOCGIFINDEX: libc::c_ulong = 0x8933;

#[cfg(target_os = "linux")]
pub struct RawChannel {
    tx: Socket,
    rx: Socket,
}

#[cfg(target_os = "linux")]
impl Clone for RawChannel {
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.try_clone().expect("Failed to dup TX raw socket fd"),
            rx: self.rx.try_clone().expect("Failed to dup RX AF_PACKET fd"),
        }
    }
}

#[cfg(target_os = "linux")]
impl RawChannel {
    /// Creates a new RawChannel. Requires CAP_NET_RAW and CAP_NET_ADMIN capabilities.
    pub fn new(iface_name: &str) -> Result<Self> {
        // TX Path: AF_INET, SOCK_RAW, IPPROTO_RAW
        // IP_HDRINCL is implied by IPPROTO_RAW on Linux (kernel won't overwrite IP header)
        let tx = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::from(255)))
            .context("Failed to create TX raw socket (needs CAP_NET_RAW)")?;
        tx.set_nonblocking(true)?;

        // RX Path: AF_PACKET, SOCK_RAW
        let rx = Socket::new(
            Domain::from(libc::AF_PACKET),
            Type::RAW,
            Some(Protocol::from(ETH_P_ALL.to_be() as libc::c_int)),
        )
        .context("Failed to create RX AF_PACKET socket (needs CAP_NET_ADMIN)")?;
        rx.set_nonblocking(true)?;

        // Bind RX to specific interface
        unsafe {
            let mut ifreq: libc::ifreq = std::mem::zeroed();
            let iface_bytes = iface_name.as_bytes();
            let len = std::cmp::min(iface_bytes.len(), libc::IFNAMSIZ - 1);
            for (i, &b) in iface_bytes[..len].iter().enumerate() {
                ifreq.ifr_name[i] = b as libc::c_char;
            }

            if libc::ioctl(rx.as_raw_fd(), SIOCGIFINDEX, &mut ifreq) < 0 {
                return Err(anyhow::anyhow!("Failed to get interface index for {}", iface_name));
            }

            let mut sll: libc::sockaddr_ll = std::mem::zeroed();
            sll.sll_family = libc::AF_PACKET as u16;
            sll.sll_protocol = ETH_P_ALL.to_be();
            sll.sll_ifindex = ifreq.ifr_ifru.ifru_ifindex;

            if libc::bind(
                rx.as_raw_fd(),
                &sll as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as u32,
            ) < 0 {
                return Err(anyhow::anyhow!("Failed to bind AF_PACKET to interface {}", iface_name));
            }
        }

        Ok(Self {
            tx,
            rx,
        })
    }

    /// Sends a batch of pre-forged raw packets sequentially via send_to.
    pub async fn send_batch(&self, packets: &[Vec<u8>]) -> Result<()> {
        for packet in packets {
            if packet.len() < 20 {
                return Err(anyhow::anyhow!("Packet too short for IP header"));
            }
            let dest = std::net::Ipv4Addr::new(
                packet[16], packet[17], packet[18], packet[19]
            );
            let dest_addr = std::net::SocketAddrV4::new(dest, 0);
            self.tx.send_to(packet, &dest_addr.into())
                .context("send_to failed on raw socket")?;
        }
        Ok(())
    }

    /// Synchronously waits and receives a packet from the AF_PACKET RX socket, up to `timeout`.
    /// Used for capturing SEQ/ACK numbers of existing sessions for Desync attacks.
    pub async fn recv_timeout(&self, timeout: Duration) -> Result<Option<Vec<u8>>> {
        let fd = self.rx.as_raw_fd();
        tokio::task::spawn_blocking(move || {
            let mut pfd = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
            let res = unsafe { libc::poll(&mut pfd, 1, timeout.as_millis() as i32) };
            if res < 0 {
                return Err(anyhow::anyhow!("poll(): {}", std::io::Error::last_os_error()));
            } else if res == 0 {
                return Ok(None);
            }
            let mut buf = vec![0u8; 65535];
            let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as _, buf.len(), 0) };
            if n < 0 {
                return Err(anyhow::anyhow!("recv(): {}", std::io::Error::last_os_error()));
            }
            buf.truncate(n as usize);
            Ok(Some(buf))
        }).await?
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::core::net_evasion::packet_forge::{IpBuilder, TcpBuilder, TCP_SYN};
    use std::net::Ipv4Addr;

    #[tokio::test]
    #[ignore = "Requires CAP_NET_RAW and CAP_NET_ADMIN"]
    async fn test_loopback_syn_capture() {
        let channel = RawChannel::new("lo").expect("Failed to bind to loopback");
        
        let src_ip = Ipv4Addr::new(127, 0, 0, 1);
        let dst_ip = Ipv4Addr::new(127, 0, 0, 1);
        
        // Build IP header
        let ip_hdr = IpBuilder::new(src_ip, dst_ip, 6)
            .with_payload_len(20) // 20 bytes of TCP header
            .build(); // 6 = TCP
        
        // Build TCP SYN
        let mut tcp = TcpBuilder::new(54321, 80)
            .with_flags(TCP_SYN)
            .with_seq(1000);
        
        let checksum = tcp.calculate_checksum(src_ip, dst_ip, &tcp.build(), &[]);
        tcp.checksum = Some(checksum);
        let tcp_hdr = tcp.build();
        
        let mut packet = ip_hdr;
        packet.extend(tcp_hdr);
        
        // Send packet
        channel.send_batch(&[packet]).await.expect("Failed to send batch");
        
        // Try to capture it via AF_PACKET
        let recv = channel.recv_timeout(Duration::from_millis(500)).await.expect("Receive error");
        
        assert!(recv.is_some(), "Did not capture any packets on loopback");
    }
}
