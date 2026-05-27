use std::net::Ipv4Addr;

pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;
pub const TCP_URG: u8 = 0x20;

/// A builder for raw IPv4 headers.
#[derive(Debug, Clone)]
pub struct IpBuilder {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub protocol: u8,
    pub ttl: u8,
    pub tos: u8,
    pub identification: u16,
    pub flags: u8,
    pub frag_offset: u16,
    pub payload_len: u16,
    pub checksum: Option<u16>,
}

impl IpBuilder {
    pub fn new(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, protocol: u8) -> Self {
        Self {
            src_ip,
            dst_ip,
            protocol,
            ttl: 64,
            tos: 0,
            identification: rand::random(),
            flags: 0,
            frag_offset: 0,
            payload_len: 0,
            checksum: None,
        }
    }

    pub fn with_ttl(mut self, ttl: u8) -> Self {
        self.ttl = ttl;
        self
    }

    pub fn with_identification(mut self, id: u16) -> Self {
        self.identification = id;
        self
    }

    /// `offset_in_8byte_units` is measured in 8-byte blocks as per RFC 791.
    /// E.g., for a 24-byte payload offset, pass 3.
    pub fn with_fragmentation(mut self, flags: u8, offset_in_8byte_units: u16) -> Self {
        self.flags = flags & 0x07;
        self.frag_offset = offset_in_8byte_units & 0x1FFF;
        self
    }

    pub fn with_payload_len(mut self, len: u16) -> Self {
        self.payload_len = len;
        self
    }

    pub fn calculate_checksum(&self, header: &[u8]) -> u16 {
        let mut sum = 0u32;
        for chunk in header.chunks(2) {
            if chunk.len() == 2 {
                sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
            } else {
                sum += u16::from_be_bytes([chunk[0], 0]) as u32;
            }
        }
        while sum > 0xFFFF {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !(sum as u16)
    }

    /// Returns the 20-byte IP header only.
    /// Caller must append payload bytes after: header + payload_bytes.
    pub fn build(&self) -> Vec<u8> {
        let mut header = vec![0u8; 20];
        
        header[0] = 0x45; // Version 4, IHL 5
        header[1] = self.tos;
        
        let total_len = 20 + self.payload_len;
        header[2..4].copy_from_slice(&total_len.to_be_bytes());
        header[4..6].copy_from_slice(&self.identification.to_be_bytes());
        
        let frag_field = ((self.flags as u16) << 13) | self.frag_offset;
        header[6..8].copy_from_slice(&frag_field.to_be_bytes());
        
        header[8] = self.ttl;
        header[9] = self.protocol;
        
        header[12..16].copy_from_slice(&self.src_ip.octets());
        header[16..20].copy_from_slice(&self.dst_ip.octets());
        
        let chk = self.checksum.unwrap_or_else(|| self.calculate_checksum(&header));
        header[10..12].copy_from_slice(&chk.to_be_bytes());
        
        header
    }
}

pub trait PacketForge {
    fn build(&self) -> Vec<u8>;
}

impl PacketForge for IpBuilder {
    fn build(&self) -> Vec<u8> {
        IpBuilder::build(self)
    }
}

/// A builder for raw TCP headers.
#[derive(Debug, Clone)]
pub struct TcpBuilder {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq_num: u32,
    pub ack_num: u32,
    pub data_offset: u8,
    pub flags: u8,
    pub window_size: u16,
    pub urgent_ptr: u16,
    pub options: Vec<u8>,
    pub checksum: Option<u16>,
}

impl TcpBuilder {
    pub fn new(src_port: u16, dst_port: u16) -> Self {
        Self {
            src_port,
            dst_port,
            seq_num: rand::random(),
            ack_num: 0,
            data_offset: 5,
            flags: 0,
            window_size: 65535,
            urgent_ptr: 0,
            options: Vec::new(),
            checksum: None,
        }
    }

    pub fn with_seq(mut self, seq: u32) -> Self {
        self.seq_num = seq;
        self
    }

    pub fn with_ack(mut self, ack: u32) -> Self {
        self.ack_num = ack;
        self
    }

    pub fn with_flags(mut self, flags: u8) -> Self {
        self.flags |= flags;
        self
    }

    pub fn with_window(mut self, window: u16) -> Self {
        self.window_size = window;
        self
    }

    pub fn with_urgent_ptr(mut self, ptr: u16) -> Self {
        self.urgent_ptr = ptr;
        if ptr > 0 {
            self.flags |= 0x20; // set URG flag
        }
        self
    }

    pub fn with_options(mut self, options: &[u8]) -> Self {
        self.options = options.to_vec();
        let len = 20 + self.options.len();
        let words = len.div_ceil(4);
        self.data_offset = words as u8;
        // Pad options to 32-bit boundary
        while !self.options.len().is_multiple_of(4) {
            self.options.push(1); // NOP (kind=1) padding
        }
        self
    }

    pub fn calculate_checksum(&self, src_ip: Ipv4Addr, dst_ip: Ipv4Addr, header: &[u8], payload: &[u8]) -> u16 {
        let mut sum = 0u32;
        
        // Pseudo header
        let src_octets = src_ip.octets();
        let dst_octets = dst_ip.octets();
        sum += u16::from_be_bytes([src_octets[0], src_octets[1]]) as u32;
        sum += u16::from_be_bytes([src_octets[2], src_octets[3]]) as u32;
        sum += u16::from_be_bytes([dst_octets[0], dst_octets[1]]) as u32;
        sum += u16::from_be_bytes([dst_octets[2], dst_octets[3]]) as u32;
        sum += 6u32; // TCP proto
        let tcp_len = (header.len() + payload.len()) as u16;
        sum += tcp_len as u32;
        
        // Header
        for chunk in header.chunks(2) {
            if chunk.len() == 2 {
                sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
            } else {
                sum += u16::from_be_bytes([chunk[0], 0]) as u32;
            }
        }
        
        // Payload
        for chunk in payload.chunks(2) {
            if chunk.len() == 2 {
                sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
            } else {
                sum += u16::from_be_bytes([chunk[0], 0]) as u32;
            }
        }
        
        while sum > 0xFFFF {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !(sum as u16)
    }

    /// Returns the TCP header only.
    /// Caller must append payload bytes after: header + payload_bytes.
    /// Note: To calculate checksum accurately, the payload is needed or checksum must be updated later.
    pub fn build(&self) -> Vec<u8> {
        let mut header = vec![0u8; (self.data_offset * 4) as usize];
        
        header[0..2].copy_from_slice(&self.src_port.to_be_bytes());
        header[2..4].copy_from_slice(&self.dst_port.to_be_bytes());
        header[4..8].copy_from_slice(&self.seq_num.to_be_bytes());
        header[8..12].copy_from_slice(&self.ack_num.to_be_bytes());
        
        header[12] = (self.data_offset << 4) & 0xF0;
        header[13] = self.flags;
        header[14..16].copy_from_slice(&self.window_size.to_be_bytes());
        
        // checksum left as 0 by default, caller must compute it with payload
        if let Some(chk) = self.checksum {
            header[16..18].copy_from_slice(&chk.to_be_bytes());
        }
        
        header[18..20].copy_from_slice(&self.urgent_ptr.to_be_bytes());
        
        if !self.options.is_empty() {
            header[20..20+self.options.len()].copy_from_slice(&self.options);
        }
        
        header
    }
}

impl PacketForge for TcpBuilder {
    fn build(&self) -> Vec<u8> {
        TcpBuilder::build(self)
    }
}

/// A builder for raw UDP headers.
#[derive(Debug, Clone)]
pub struct UdpBuilder {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: Option<u16>,
}

impl UdpBuilder {
    pub fn new(src_port: u16, dst_port: u16) -> Self {
        Self {
            src_port,
            dst_port,
            length: 8,
            checksum: None,
        }
    }

    pub fn with_payload_len(mut self, len: u16) -> Self {
        self.length = 8 + len;
        self
    }

    pub fn calculate_checksum(&self, src_ip: Ipv4Addr, dst_ip: Ipv4Addr, header: &[u8], payload: &[u8]) -> u16 {
        let mut sum = 0u32;
        
        let src_octets = src_ip.octets();
        let dst_octets = dst_ip.octets();
        sum += u16::from_be_bytes([src_octets[0], src_octets[1]]) as u32;
        sum += u16::from_be_bytes([src_octets[2], src_octets[3]]) as u32;
        sum += u16::from_be_bytes([dst_octets[0], dst_octets[1]]) as u32;
        sum += u16::from_be_bytes([dst_octets[2], dst_octets[3]]) as u32;
        sum += 17u32; // UDP proto
        let udp_len = (header.len() + payload.len()) as u16;
        sum += udp_len as u32;
        
        for chunk in header.chunks(2) {
            if chunk.len() == 2 { sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32; }
            else { sum += u16::from_be_bytes([chunk[0], 0]) as u32; }
        }
        for chunk in payload.chunks(2) {
            if chunk.len() == 2 { sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32; }
            else { sum += u16::from_be_bytes([chunk[0], 0]) as u32; }
        }
        
        while sum > 0xFFFF { sum = (sum & 0xFFFF) + (sum >> 16); }
        let chk = !(sum as u16);
        if chk == 0 { 0xFFFF } else { chk }
    }

    /// Returns the 8-byte UDP header. Caller appends payload.
    pub fn build(&self) -> Vec<u8> {
        let mut header = vec![0u8; 8];
        header[0..2].copy_from_slice(&self.src_port.to_be_bytes());
        header[2..4].copy_from_slice(&self.dst_port.to_be_bytes());
        header[4..6].copy_from_slice(&self.length.to_be_bytes());
        if let Some(chk) = self.checksum {
            header[6..8].copy_from_slice(&chk.to_be_bytes());
        }
        header
    }
}

impl PacketForge for UdpBuilder {
    fn build(&self) -> Vec<u8> {
        UdpBuilder::build(self)
    }
}

/// A builder for raw ICMP headers.
#[derive(Debug, Clone)]
pub struct IcmpBuilder {
    pub icmp_type: u8,
    pub code: u8,
    pub id: u16,
    pub seq: u16,
    pub checksum: Option<u16>,
}

impl IcmpBuilder {
    pub fn new(icmp_type: u8, code: u8) -> Self {
        Self {
            icmp_type,
            code,
            id: rand::random(),
            seq: 1,
            checksum: None,
        }
    }

    pub fn with_id_seq(mut self, id: u16, seq: u16) -> Self {
        self.id = id;
        self.seq = seq;
        self
    }

    pub fn calculate_checksum(&self, header: &[u8], payload: &[u8]) -> u16 {
        let mut sum = 0u32;
        for chunk in header.chunks(2) {
            if chunk.len() == 2 { sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32; }
            else { sum += u16::from_be_bytes([chunk[0], 0]) as u32; }
        }
        for chunk in payload.chunks(2) {
            if chunk.len() == 2 { sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32; }
            else { sum += u16::from_be_bytes([chunk[0], 0]) as u32; }
        }
        while sum > 0xFFFF { sum = (sum & 0xFFFF) + (sum >> 16); }
        !(sum as u16)
    }

    /// Returns the 8-byte ICMP header (type, code, checksum, id, seq).
    pub fn build(&self) -> Vec<u8> {
        let mut header = vec![0u8; 8];
        header[0] = self.icmp_type;
        header[1] = self.code;
        if let Some(chk) = self.checksum {
            header[2..4].copy_from_slice(&chk.to_be_bytes());
        }
        header[4..6].copy_from_slice(&self.id.to_be_bytes());
        header[6..8].copy_from_slice(&self.seq.to_be_bytes());
        header
    }
}

impl PacketForge for IcmpBuilder {
    fn build(&self) -> Vec<u8> {
        IcmpBuilder::build(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_ip_builder_checksum() {
        let builder = IpBuilder::new(
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(8, 8, 8, 8),
            6 // TCP
        ).with_ttl(64).with_payload_len(20); // 20 bytes of TCP header

        let packet = builder.build();
        
        // Basic header checks
        assert_eq!(packet[0], 0x45);
        assert_eq!(packet[8], 64); // TTL
        assert_eq!(packet[9], 6);  // Proto
        
        // Ensure checksum isn't zero
        let chk = u16::from_be_bytes([packet[10], packet[11]]);
        assert_ne!(chk, 0);
        
        // Verifying checksum calculation
        let mut sum = 0u32;
        for chunk in packet.chunks(2) {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        }
        while sum > 0xFFFF {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        assert_eq!(sum, 0xFFFF);
    }
}
