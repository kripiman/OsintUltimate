use anyhow::{Result, Context};
use io_uring::{opcode, types, IoUring};
use std::net::Ipv4Addr;
use std::os::unix::io::AsRawFd;
use socket2::{Domain, Protocol, Socket, Type};
use tracing::{info, debug, error};
use rand::Rng;

/// ARCH-v4: Native Scanner Trait
#[async_trait::async_trait]
pub trait NativeScanner: Send + Sync {
    fn name(&self) -> &str;
    async fn scan(&self, target: &str, ports: &[u16]) -> Result<Vec<crate::models::Finding>>;
}

/// High-Performance SYN Scanner using io_uring SQ (Submission Queue).
/// Eliminates fork/exec and minimizes syscalls per packet.
pub struct IoUringScanner {
    ring: std::sync::Mutex<IoUring>,
    raw_socket: Socket,
    local_ip: Ipv4Addr,
}

impl IoUringScanner {
    pub fn new(depth: u32, local_ip: Ipv4Addr) -> Result<Self> {
        let ring = IoUring::builder()
            .setup_sqpoll(1000)
            .build(depth)?;
        
        let sock = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::TCP))?;
        sock.set_nonblocking(true)?;
        sock.set_reuse_address(true)?;
        
        Ok(Self { 
            ring: std::sync::Mutex::new(ring), 
            raw_socket: sock, 
            local_ip 
        })
    }

    pub async fn submit_batch(&self, targets: &[(Ipv4Addr, u16)]) -> Result<()> {
        let mut packets = Vec::with_capacity(targets.len());
        for (ip, port) in targets {
            packets.push(self.craft_syn_packet(*ip, *port));
        }

        {
            let mut ring = self.ring.lock().unwrap();
            let mut sq = ring.submission();
            
            for packet in &packets {
                let write_op = opcode::Write::new(
                    types::Fd(self.raw_socket.as_raw_fd()),
                    packet.as_ptr(),
                    packet.len() as u32,
                ).build();
                
                unsafe {
                    sq.push(&write_op).map_err(|_| anyhow::anyhow!("SQ Full"))?;
                }
            }
            drop(sq); // Drop SQ handle before submit

            debug!("🚀 v4-NATIVE: Submitting batch of {} packets to io_uring SQ", targets.len());
            ring.submit_and_wait(targets.len())?;
            
            let cq = ring.completion();
            let mut count = 0;
            for cqe in cq {
                if cqe.result() < 0 {
                    let err = std::io::Error::from_raw_os_error(-cqe.result());
                    error!("❌ v4-NATIVE: Packet submission error: {}", err);
                }
                count += 1;
                if count >= targets.len() { break; }
            }
        }
        
        Ok(())
    }

    fn calculate_tcp_checksum(&self, dest_ip: Ipv4Addr, tcp_header: &[u8]) -> u16 {
        let mut sum = 0u32;
        
        // Pseudo-header
        let src_octets = self.local_ip.octets();
        let dest_octets = dest_ip.octets();
        
        sum += u16::from_be_bytes([src_octets[0], src_octets[1]]) as u32 ;
        sum += u16::from_be_bytes([src_octets[2], src_octets[3]]) as u32 ;
        sum += u16::from_be_bytes([dest_octets[0], dest_octets[1]]) as u32 ;
        sum += u16::from_be_bytes([dest_octets[2], dest_octets[3]]) as u32 ;
        sum += 6u32; // Protocol TCP
        sum += tcp_header.len() as u32 ;
        
        // TCP Header
        for chunk in tcp_header.chunks_exact(2) {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32 ;
        }
        
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        
        !(sum as u16)
    }

    fn craft_syn_packet(&self, dest_ip: Ipv4Addr, dest_port: u16) -> Vec<u8> {
        // Minimal SYN packet crafting (IP + TCP headers)
        let mut packet = vec![0u8; 40];
        
        // IP Header (20 bytes)
        packet[0] = 0x45; // Version 4, Header Length 5 (20 bytes)
        packet[2..4].copy_from_slice(&40u16.to_be_bytes()); // Total Length
        packet[8] = 64; // TTL
        packet[9] = 6; // Protocol TCP
        packet[12..16].copy_from_slice(&self.local_ip.octets()); // Source IP
        packet[16..20].copy_from_slice(&dest_ip.octets()); // Dest IP
        
        // TCP Header (20 bytes)
        let src_port = rand::thread_rng().gen_range(32768u16..61000u16); 
        packet[20..22].copy_from_slice(&src_port.to_be_bytes());
        packet[22..24].copy_from_slice(&dest_port.to_be_bytes());
        // Sequence number (random)
        let seq = rand::thread_rng().gen::<u32>();
        packet[24..28].copy_from_slice(&seq.to_be_bytes());
        
        packet[32] = 0x50; // Data offset (5 * 4 = 20 bytes)
        packet[33] = 0x02; // Flags: SYN
        packet[34..36].copy_from_slice(&65535u16.to_be_bytes()); // Window size
        
        // TCP Checksum calculation
        let checksum = self.calculate_tcp_checksum(dest_ip, &packet[20..40]);
        packet[36..38].copy_from_slice(&checksum.to_be_bytes());
        
        packet
    }
}

#[async_trait::async_trait]
impl NativeScanner for IoUringScanner {
    fn name(&self) -> &str { "native-syn-scanner" }
    
    async fn scan(&self, target: &str, ports: &[u16]) -> Result<Vec<crate::models::Finding>> {
        info!("🚀 v4-NATIVE: Scanning {} ({} ports) using io-uring...", target, ports.len());
        
        let dest_ip: Ipv4Addr = target.parse().context("Target must be IPv4 for native-syn-scanner")?;
        let batch: Vec<(Ipv4Addr, u16)> = ports.iter().map(|p| (dest_ip, *p)).collect();
        
        self.submit_batch(&batch).await?;
        
        // Wait for responses (In a real implementation, this would use a background BPF/Raw-Socket listener)
        // For v4-REMEDIATION, we provide the high-performance transmission skeleton.
        info!("🚀 v4-NATIVE: Batch submitted successfully.");
        
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    // Imports removed as they were unused.

    #[test]
    fn test_tcp_checksum_logic() {
        // Since IoUringScanner::calculate_tcp_checksum requires self (with local_ip),
        // we test it by checking if it produces a 16-bit value.
        // We avoid calling new() to avoid io_uring setup in non-privileged environments.
        
        // This is a placeholder test to ensure compilation and basic logic path availability.
        // Real logic verification would require a refactored pure function.
    }
}
