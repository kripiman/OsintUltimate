# SEC-004 Sandbox Spike — FluidLocal Tier Hardening for net_evasion

## Status
Spike complete. No production code changes. Risk register updated.

## Context

`SandboxDispatcher` has three execution tiers:

| Tier | Isolation | net_evation Exposure |
|---|---|---|
| `StrictDocker` | `--cap-drop=ALL`, `--security-opt no-new-privileges`, `--user 1000:1000`, selective `CAP_NET_RAW` | Controlled via Docker |
| `FluidLocal` | `setpgid` only (PGID isolation). **No seccomp, no namespaces.** | **Unrestricted** |
| `Wasm` | wasmi runtime | N/A (WASM memory sandbox) |

`FluidLocal` is selected for scanners/OSINT on low-RAM systems. However, `net_evasion` modules (raw sockets, packet forging, XDP) may execute in `FluidLocal` if the tool category is not `exploitation`.

## net_evasion Syscall Profile

### raw_socket.rs — RawChannel
Requires: `CAP_NET_RAW` + `CAP_NET_ADMIN`
Syscalls used:
- `socket(AF_INET, SOCK_RAW, IPPROTO_RAW)` — TX raw IP
- `socket(AF_PACKET, SOCK_RAW, ETH_P_ALL)` — RX L2
- `ioctl(SIOCGIFINDEX)` — interface index lookup
- `bind(sockaddr_ll)` — bind RX to interface
- `setsockopt` (via `socket2` crate: `SO_NONBLOCK`)
- `poll(POLLIN)` — wait for RX
- `recv()` — read packet
- `sendto()` — send packet

### af_xdp_channel.rs — AF_XDP scaffold
Requires: `CAP_NET_ADMIN` + `CAP_IPC_LOCK`
Syscalls used:
- `socket(AF_XDP, SOCK_RAW, 0)`
- `setsockopt(SOL_XDP, XDP_UMEM_REG)`
- `setsockopt(SOL_XDP, XDP_TX_RING)`
- `mmap()` — ring buffer mapping
- `bind(sockaddr_xdp)`
- `sendto()` — TX wake
- `munmap()` — cleanup
- `close()` — cleanup
- `if_nametoindex()` — interface resolution

### tcp_session.rs — TCP state machine over raw sockets
Requires: `CAP_NET_RAW` + `CAP_NET_ADMIN` (same as RawChannel)
**Additional critical vector:** Executes `iptables` as a subprocess:
```rust
Command::new("iptables").args([...]).status()
```
This uses `fork`/`clone` + `execve` syscalls. Any seccomp filter that blocks `execve` would break `TcpSession` entirely.

### topology_prober.rs — TTL traceroute
Requires: `CAP_NET_RAW` + `CAP_NET_ADMIN`
Uses `RawChannel` (same syscalls as raw_socket.rs). No subprocess.

## seccomp-bpf Viability Analysis

### Option A: Strict seccomp whitelist
Allow: `socket`, `bind`, `ioctl`, `setsockopt`, `poll`, `recv`, `recvfrom`, `send`, `sendto`, `mmap`, `munmap`, `close`, `read`, `write`, `if_nametoindex`, `getifaddrs`, `freeifaddrs`.

**Block:** `execve`, `execveat`, `fork`, `vfork`, `clone`.

**Result:** `tcp_session.rs` breaks because it needs `iptables` subprocess. `raw_socket.rs`, `af_xdp_channel.rs`, `topology_prober.rs` would work.

### Option B: Permissive seccomp (allow execve)
Allow everything in Option A + `execve`, `fork`, `clone`, `wait4`.

**Result:** `tcp_session.rs` works, but the sandbox is significantly weaker. A compromised plugin could spawn arbitrary subprocesses (`/bin/sh`, `curl`, etc.).

### Option C: Replace iptables subprocess with netlink/NFTables
Rewrite `TcpSession` to manipulate packet filtering via `netlink` socket (`AF_NETLINK`) instead of `iptables` command. This removes the `execve` requirement.

**Effort:** High. NFTables netlink protocol is complex. Would require a new crate dependency (`nftables` or raw netlink) and significant refactoring.
**Risk:** iptables is well-tested for RST suppression; NFTables equivalent may behave differently across kernel versions.

### Option D: CLONE_NEWNET namespace
Use `unshare(CLONE_NEWNET)` before spawning the net_evasion process.

**Result:** The process gets its own network namespace with only a loopback interface. It cannot reach external targets. **Completely breaks scanner functionality.**

Verdict: **Inviable for OSINT/scanners.** Only useful for pure offline packet analysis, which is not the net_evasion use case.

## Risk Register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Malicious plugin in FluidLocal uses raw sockets for network attacks | Low (FluidLocal selected for OSINT, not exploitation) | High | Force `StrictDocker` for any tool loading net_evasion modules |
| Plugin escapes via `iptables` subprocess manipulation | Low | High | `iptables` requires root/CAP_NET_ADMIN; FluidLocal runs as non-root in production |
| AF_XDP UMEM exhaustion (DoS) | Low | Medium | UMEM size is hardcoded small (4 frames × 4KB); not user-controlled |
| `poll()`/`recv()` blocking indefinitely | Low | Medium | Timeouts are enforced (500ms default) |

## Recommendations

1. **Do NOT apply seccomp to FluidLocal in this sprint.** The `execve` requirement from `tcp_session.rs` makes strict seccomp non-viable without major refactoring.

2. **Enforce StrictDocker for net_evasion tools.** Modify `SandboxDispatcher::determine_tier` to force `StrictDocker` for any tool whose BlackArch category maps to `net_evasion` capabilities (currently only `exploitation` forces StrictDocker). This mirrors the existing safety rule for exploits.

3. **Defer NFTables migration** to a dedicated sprint if `execve`-less sandbox is required.

4. **Document residual risk** in `SandboxDispatcher` comments: "FluidLocal tier does not restrict raw socket creation. net_evasion tools MUST run under StrictDocker in untrusted environments."

## Residual Risk Acceptance

Cross-FFI provenance and dangling pointers (SEC-002) were addressed. The remaining risk is **host-level capability exposure in FluidLocal**. Accepted with mitigation #2 (force StrictDocker for net_evasion).
