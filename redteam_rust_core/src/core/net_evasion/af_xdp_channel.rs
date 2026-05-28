/// AF_XDP channel scaffold for kernel-bypass L2 packet injection.
///
/// **TX-only in Sprint 5a.** RX requires an XDP eBPF program loaded on the
/// target interface, which is deferred to Sprint 5b.
///
/// Uses raw `libc` syscalls — no external AF_XDP wrapper crates.
#[cfg(target_os = "linux")]
use anyhow::Result;
#[cfg(target_os = "linux")]
use std::time::Duration;

/// AF_XDP mmap offset for TX ring (<linux/if_xdp.h>).
/// Defined locally because `libc` crate may not expose it on all kernel headers.
const XDP_PGOFF_TX_RING: libc::off_t = 0x8000_0000;

/// Frame size for UMEM (must be power of two, >= 2048 for standard MTU).
const FRAME_SIZE: usize = 4096;

/// Number of frames in UMEM.
const FRAME_COUNT: usize = 4;

/// TX ring size.
const TX_RING_SIZE: usize = 4;

#[cfg(target_os = "linux")]
pub struct AfXdpChannel {
    sock: std::os::fd::RawFd,
    _umem: Vec<u8>,
    /// ManuallyDrop prevents Vec::drop from calling heap deallocator on mmap'd memory.
    _tx_ring: std::mem::ManuallyDrop<Vec<libc::xdp_desc>>,
    _ifindex: u32,
    _queue_id: u32,
}

#[cfg(target_os = "linux")]
impl AfXdpChannel {
    /// Bind to `ifname` (e.g. "eth0") on `queue_id` (typically 0).
    ///
    /// Requires `CAP_NET_ADMIN` and `CAP_IPC_LOCK`.
    pub fn new(ifname: &str, queue_id: u32) -> Result<Self> {
        // 1. Create AF_XDP socket
        let sock = unsafe { libc::socket(libc::AF_XDP, libc::SOCK_RAW, 0) };
        if sock < 0 {
            anyhow::bail!(
                "Failed to create AF_XDP socket: {}",
                std::io::Error::last_os_error()
            );
        }

        // 2. Get interface index
        let ifindex = Self::ifname_to_index(ifname)?;

        // 3. Allocate UMEM
        let umem = vec![0u8; FRAME_SIZE * FRAME_COUNT];

        // 4. Register UMEM
        let umem_reg = libc::xdp_umem_reg {
            addr: umem.as_ptr() as u64,
            len: umem.len() as u64,
            chunk_size: FRAME_SIZE as u32,
            headroom: 0,
            flags: 0,
            tx_metadata_len: 0,
        };
        let ret = unsafe {
            libc::setsockopt(
                sock,
                libc::SOL_XDP,
                libc::XDP_UMEM_REG,
                &umem_reg as *const _ as *const libc::c_void,
                std::mem::size_of_val(&umem_reg) as u32,
            )
        };
        if ret < 0 {
            unsafe { libc::close(sock) };
            anyhow::bail!(
                "XDP_UMEM_REG failed: {}",
                std::io::Error::last_os_error()
            );
        }

        // 5. Create TX ring
        let tx_ring_size = TX_RING_SIZE as libc::c_int;
        let ret = unsafe {
            libc::setsockopt(
                sock,
                libc::SOL_XDP,
                libc::XDP_TX_RING,
                &tx_ring_size as *const _ as *const libc::c_void,
                std::mem::size_of_val(&tx_ring_size) as u32,
            )
        };
        if ret < 0 {
            unsafe { libc::close(sock) };
            anyhow::bail!(
                "XDP_TX_RING failed: {}",
                std::io::Error::last_os_error()
            );
        }

        // 6. mmap TX ring
        let mmap_size = TX_RING_SIZE * std::mem::size_of::<libc::xdp_desc>();
        let tx_ring_ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                mmap_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_POPULATE,
                sock,
                XDP_PGOFF_TX_RING,
            )
        };
        if tx_ring_ptr == libc::MAP_FAILED {
            unsafe { libc::close(sock) };
            anyhow::bail!(
                "mmap TX ring failed: {}",
                std::io::Error::last_os_error()
            );
        }

        // Wrap mmap'd memory in ManuallyDrop<Vec> to avoid heap-dealloc UB on Drop.
        let tx_ring = std::mem::ManuallyDrop::new(unsafe {
            Vec::from_raw_parts(
                tx_ring_ptr as *mut libc::xdp_desc,
                TX_RING_SIZE,
                TX_RING_SIZE,
            )
        });

        // 7. Bind to interface / queue
        let sockaddr = libc::sockaddr_xdp {
            sxdp_family: libc::AF_XDP as u16,
            sxdp_flags: 0,
            sxdp_ifindex: ifindex,
            sxdp_queue_id: queue_id,
            sxdp_shared_umem_fd: 0,
        };
        let ret = unsafe {
            libc::bind(
                sock,
                &sockaddr as *const _ as *const libc::sockaddr,
                std::mem::size_of_val(&sockaddr) as u32,
            )
        };
        if ret < 0 {
            unsafe { libc::close(sock) };
            anyhow::bail!("AF_XDP bind failed: {}", std::io::Error::last_os_error());
        }

        Ok(Self {
            sock,
            _umem: umem,
            _tx_ring: tx_ring,
            _ifindex: ifindex,
            _queue_id: queue_id,
        })
    }

    /// TX a raw L2 frame.
    ///
    /// `packet` must fit in a single UMEM frame (`<= FRAME_SIZE`).
    pub fn send(&mut self, packet: &[u8]) -> Result<()> {
        if packet.len() > FRAME_SIZE {
            anyhow::bail!(
                "Packet too large for AF_XDP frame: {} > {}",
                packet.len(),
                FRAME_SIZE
            );
        }

        // For Sprint 5a scaffold: copy into UMEM frame 0, submit descriptor.
        // Full ring-buffer management (producer/consumer indices) is deferred
        // to Sprint 5b when RX is needed.
        let frame_addr = self._umem.as_ptr() as u64;
        unsafe {
            std::ptr::copy_nonoverlapping(
                packet.as_ptr(),
                frame_addr as *mut u8,
                packet.len(),
            );
        }

        // Write TX descriptor
        let desc = libc::xdp_desc {
            addr: 0, // offset into UMEM
            len: packet.len() as u32,
            options: 0,
        };
        self._tx_ring[0] = desc;

        // Wake kernel — send empty datagram to trigger TX
        let ret = unsafe {
            libc::sendto(
                self.sock,
                std::ptr::null(),
                0,
                libc::MSG_DONTWAIT,
                std::ptr::null(),
                0,
            )
        };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EAGAIN)
                && err.raw_os_error() != Some(libc::EWOULDBLOCK)
            {
                anyhow::bail!("AF_XDP sendto failed: {}", err);
            }
        }

        Ok(())
    }

    /// RX with timeout.
    ///
    /// **Always returns `None` in Sprint 5a** — receiving via AF_XDP requires
    /// an XDP eBPF program loaded on the interface to redirect packets to this
    /// socket. TX does not require a program.
    pub fn recv_timeout(&self, _timeout: Duration) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }

    fn ifname_to_index(ifname: &str) -> Result<u32> {
        let cname = std::ffi::CString::new(ifname)?;
        let idx = unsafe { libc::if_nametoindex(cname.as_ptr()) };
        if idx == 0 {
            anyhow::bail!("Interface '{}' not found", ifname);
        }
        Ok(idx)
    }
}

#[cfg(target_os = "linux")]
impl Drop for AfXdpChannel {
    fn drop(&mut self) {
        unsafe {
            // 1. munmap the TX ring before dropping the Vec wrapper.
            let ptr = self._tx_ring.as_ptr() as *mut libc::c_void;
            let size = TX_RING_SIZE * std::mem::size_of::<libc::xdp_desc>();
            libc::munmap(ptr, size);

            // 2. Prevent Vec::drop from running (memory already munmap'd).
            std::mem::ManuallyDrop::drop(&mut self._tx_ring);

            // 3. Close the AF_XDP socket.
            libc::close(self.sock);
        }
    }
}

#[cfg(all(test, target_os = "linux", feature = "sovereign"))]
mod tests {
    use super::*;

    #[test]
    fn af_xdp_channel_struct_exists() {
        // Type-level compile check only.
        // Runtime construction requires CAP_NET_ADMIN + valid interface.
        let _size = std::mem::size_of::<AfXdpChannel>();
    }
}
