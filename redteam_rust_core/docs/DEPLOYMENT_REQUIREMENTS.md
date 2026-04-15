# ⚙️ Deployment Requirements (MVP vs. Sovereign)

This document outlines the infrastructure, software, and API requirements to deploy OsintUltimate V14.1. The system scales dynamically based on the resources provided, ranging from a bare-minimum local testing environment to a fully autonomous, production-grade Sovereign Operator.

---

## 1. Minimal Viable Product (MVP)
The baseline requirement for the engine to execute without OPSEC guarantees. Suitable for CTFs, local labs, or authorized internal penetration testing.

### System & Core
- **OS**: Linux (Debian, Ubuntu, or Kali).
- **Runtime**: Rust `cargo` (for compilation) and `glibc`.
- **Hardware**: 1GB RAM, 1 CPU Core. (The `MemoryMonitor` will automatically detect low RAM and reduce thread concurrency and disable heavy sandboxing).

### Essential Binaries (BlackArch Fallback)
The engine will try to use embedded versions if available, but installing these locally is highly recommended for stability via `utils::tool_detection`:
- `nmap`
- `ffuf`
- `nuclei`
- `sqlmap`

### Networking & Proxies
- **Proxy**: None required.
- **OPSEC Output**: **FAIL-OPEN** (Direct connections are made. Your real IP will be logged by the target).

### APIs & Intelligence
- **AI Router**: Local Ollama execution (e.g., run `ollama serve` with `llama3`). No paid API keys required.

---

## 2. Maximum Sovereign Deployment (Production Grade)
The ultimate configuration for autonomous, non-attributable Red Teaming operations as defined by the [SOVEREIGN_SYSTEMS.md](./SOVEREIGN_SYSTEMS.md) standard. 

### System & Infrastructure
- **OS**: BlackArch Linux (for native tool integration) or a hardened Debian server.
- **Hardware**: 8GB+ RAM, 4+ CPU Cores (Required to max out the `JoinSet` concurrent worker pool and `io-uring` packet dispatch queues).
- **Kernel**: `io-uring` support enabled for `NativeScanner` high-throughput operations.

### Egress & Proxies (Mandatory)
For the system to operate in sovereign mode, the `ProxyManager` MUST have an available egress route.
- **Primary Method**: Set the `GLOBAL_SCAN_PROXY` environment variable (e.g., `export GLOBAL_SCAN_PROXY=socks5h://127.0.0.1:9050` utilizing a Tor daemon or commercial proxy pool).
- **Autonomous Provisioning Method**: Provide a **DigitalOcean API Key**. The system will autonomously spin up and destroy ephemeral 'Droplet' proxies via SSH tunneling upon WAF/403 detections.
- **Tool Dependency**: `proxychains4` MUST be installed on the host. The `StealthExecutor` uses this to forcibly wrap external binaries to prevent IP leaks.

### Professional C2 Binaries
To reach Phase 4 & Phase 5 of the offensive lifecycle, the following must be installed:
- `sliver-server` (For mTLS Sovereign Implants).
- `ligolo-proxy` (For Layer 3 Agent pivoting and Managed Exit tunneling).
- `bloodhound-python` (For AD Graph ingestion).

### Commercial APIs (TieredAIRouter & Recon)
- **Primary AI Engines**: 
  - `OPENAI_API_KEY` (Required for complex PoC generation and DFS attack path reasoning).
  - `ANTHROPIC_API_KEY` (Used for code/context-heavy exploit generation).
- **OSINT Enrichment**:
  - `SHODAN_API_KEY`
  - `NETLAS_API_KEY` (Optimized for Freelancer tier).
  - `CHAOS_API_KEY` (Free ProjectDiscovery tokens).
  - `SECURITYTRAILS_API_KEY`
  - `CRIMINALIP_API_KEY`
  - `NETLAS_DAILY_BUDGET` (Default: 33).
  - `CENSYS_API_ID` & `CENSYS_API_SECRET`
  - `GITHUB_TOKEN` (Crucial for `TruffleHogScanner` and `GitleaksScanner` authenticated deep-dives without rate limits).

---

## 3. Compatible Proxy Implementations

To fulfill the `GLOBAL_SCAN_PROXY` requirement for Sovereign routing, OsintUltimate is agnostic to the backend protocol as long as it exposes a **SOCKS5** interface. Here are the recommended implementations for red-teaming:

### A. Local SOCKS5 Daemons (High Stealth)
- **Tor Daemon (`tor`)**: The easiest way to achieve instant anonymity.
  - Setup: Install `tor` and expose `127.0.0.1:9050`.
  - Pro: Free, high anonymity, IP rotates automatically.
  - Con: High latency (bad for WebFuzzer), frequently blocked by WAFs.
- **SSH Dynamic Port Forwarding (`ssh -D`)**: The industry standard for Red Teams.
  - Setup: `ssh -D 1080 -q -C -N user@your-vps-ip`.
  - Pro: Fast, encrypts all traffic to the VPS, uses your own clean infrastructure.
  - Con: Requires an external server.

### B. Network Proxy Services (High Throughput)
- **Dante (`danted`)**: A highly scalable enterprise SOCKS server.
  - Setup: Installed on your cloud infrastructure.
  - Pro: Handles thousands of concurrent connections (ideal for Nmap/Nuclei).
  - Con: Requires manual configuration and hardening.
- **Shadowsocks**: An encrypted proxy protocol.
  - Pro: Excellent for bypassing Deep Packet Inspection (DPI).

### C. Commercial API/Autonomous (High Evasiveness)
- **DigitalOcean Autonomous Egress**: OsintUltimate natively supports spinning up ephemeral DigitalOcean 'Droplets'.
  - Setup: Provide `DIGITALOCEAN_TOKEN`.
  - How it Works: When `SwarmOrchestrator` detects heavy WAF blocking, it uses the DO API to spawn a new server, establishes an SSH tunnel (`ssh -D`) or Shadowsocks relay, routes the `ProxyManager` through it, and destroys the server after the mission.
- **Commercial Proxy Pools**: (e.g., BrightData, ProxyMesh)
  - Setup: Set `GLOBAL_SCAN_PROXY=socks5://user:pass@pool.example.com`.
  - Pro: Millions of rotating residential IPs. Practically immune to rate-limiting.

---

## 4. High-Speed Proxy Optimizations

To reduce the latency of autonomous provisioning (~60s JIT delay) and improve throughput, the following strategies are recommended:

### A. Protocol Switch: Shadowsocks vs SSH
**Shadowsocks is FREE** and open-source. The only cost is the VPS hosting (e.g., your DigitalOcean droplet).
- **Why it's faster**: While SSH Tunnels (`-D`) are standard, they suffer from high protocol overhead and TCP-over-TCP congestion. Shadowsocks provides near-native network speeds and handles packet loss significantly better during high-speed scans.
- **Implementation**: Set `PROXY_MODE=shadowsocks` in the `.env`. The orchestrator will then deploy a Dockerized Shadowsocks instance on the DO Droplet instead of using the SSH binary.

### B. Pre-Warmed Proxy Pools (Warm-Start)
To eliminate the 1-minute spin-up delay:
- **Warm Pool Size**: Configure `PROXY_POOL_SIZE=3`.
- **Operational Logic**: The system will keep 3 droplets "Warm" (already started and healthy). When an agent needs to rotate due to a block, it switches to a Warm node instantly (0ms delay) while the orchestrator starts a new droplet in the background to replenish the pool.

- **Setup Strategy**: Set `PROXY_MODE=hysteria`.
- **Hysteria Advantage**: It uses **QUIC/UDP** on port 1080. It is immune to many forms of bandwidth throttling and provides extreme stability during multi-threaded reconnaissance.
- **Auto-Servicing**: OsintUltimate automatically downloads the necessary hysteria binary to your local host (`~/.local/share/osintultimate/bin`) to facilitate the client-side connection to your sovereign nodes.

---

## 5. Summary of Sovereign Egress (V14.1)

| Mode | Protocol | Use Case | Latency (ms) |
| :--- | :--- | :--- | :--- |
| **Dante (SOCKS5)** | TCP | Standard stealth scanning | ~150-300 |
| **Shadowsocks** | TCP/TLS | DPI Evasion, high-speed Nmap | ~100-200 |
| **Hysteria** | QUIC/UDP | Extreme-speed recon, low stability links | ~30-80 |

### Global Kill-Switch
*   **Trigger**: `Ctrl+C` / Interrupt.
*   **Action**: Immediate autonomous destruction of all active droplets under the `osint-ultimate` tag. No cloud leaks.
  1. **Server-Side**: The orchestrator sends a `cloud-init` script to the DO API that installs the `hysteria` server binary, configured to listen on a random high UDP port.
  2. **Client-Side**: OsintUltimate spawns a local `hysteria` client process that connects to the Droplet's UDP port.
  3. **Interface**: The local Hysteria client exposes a local SOCKS5 listener (e.g., `127.0.0.1:1080`).
  4. **Integration**: `ProxyManager` is then configured to use this local listener as the egress gate.
- **Why use it?**: It uses QUIC to bypass bandwidth throttling and provides extreme stability for C2 channels in high-latency environments.

---

## 4. Quick Reference Matrix

| Feature | Local MVP | Sovereign Production | Documentation |
| :--- | :--- | :--- | :--- |
| **Origin IP** | Direct (Logged) | SOCKS5 / Tor / Ephemeral | [Hardening Guide](./HARDENING_AND_OPSEC.md) |
| **Cmd Wrapping** | Standard `Command::new` | Env-Cleared + `proxychains4` | `src/utils/executor.rs` |
| **AI Generation** | Ollama (Local) | GPT-4o / Claude 3.5 Sonnet | `src/core/validation/mod.rs` |
| **Resource Limits** | Native OS default | `rlimit` (512MB RAM/300s CPU) | `src/utils/common.rs` |
| **C2 Support** | Fallback CLI | Sliver OTT + Ligolo Tunnels | Phase 4 Lifecycle |
