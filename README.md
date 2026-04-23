<p align="center">
  <img src="mimicry_logo.png" width="200" alt="OsintUltimate Mimicry Octopus">
</p>

# 🔱 OsintUltimate (V14.1 Sovereign Stealth Protocol)

> **Autonomous Red Team Orchestration & Sovereign Offensive Operations**
> 
> *Binary Precision. Fail-Closed Egress. Sovereign Command.*
> *V14.1 Protocol: Adaptive Posture Management, Priority Swarm Dynamics, and AttackGraph Correlation.*

---

## ✅ Production Readiness Status: **READY**
**OsintUltimate V14.1** has passed the full **GHOST/STRIKE/BREACH** audit cycle.
- **Zero Technical Debt**: Case-verified Clippy-0 codebase.
- **Hardened Egress**: Production-ready stealth infrastructure with autonomous VPS lifecycle management.
- **Safety**: Integrated `ApprovalGate` and `Kill-Switch` for controlled offensive operations.

---

## ⚙️ How It Works (The Sovereign Engine)

OsintUltimate is not a simple scanner; it is an **Autonomous Multi-Agent Swarm** that operates through a cognitive feedback loop:

1.  **Planning (Swarm Orchestrator)**: The system decomposes a target into atomic tasks. Agents are spawned to handle specific vectors (Web, Network, Cloud, OSINT).
2.  **Cognition (AI Router & Judge)**: Every finding is processed by a tiered AI system. 
    - *Local LLMs (Ollama)* handle high-volume noise filtering.
    - *Premium LLMs (OpenAI/Anthropic)* perform complex tactical decision-making and exploit planning.
3.  **Execution (Plugin Pipeline)**: Tasks are executed via a unified FFI boundary or isolated Docker containers, leveraging dozens of integrated industry tools.
4.  **Stealth Networking (Fail-Closed Egress)**: All traffic is routed through encrypted tunnels (Shadowsocks/Hysteria) on ephemeral VPS nodes. If a proxy is compromised or hangs, the "Fail-Closed" mechanism terminates all traffic instantly to prevent IP leakage.
5.  **Persistence & Correlation**: Findings are stored in an ACID-compliant SQLite engine and correlated via an **AttackGraph** to find pivoting opportunities (e.g., AD Escalation).

---

## 🛠️ Dependencies & Requirements

To operate at its full "Sovereign" potential, the following components are required:

### 1. System Dependencies
- **Rust (Stable)**: Core engine build and execution.
- **Docker**: Essential for running third-party security tools (Plugins) in isolated environments.
- **SQLite 3**: Local persistence for findings and state tracking.
- **OpenSSL / Libssl-dev**: Required for encrypted communications.

### 2. Infrastructure & API Keys (Configured via `.env`)
- **DigitalOcean Token**: Mandatory for the **Stealth VPS** rotation.
- **AI Backend**:
    - **Ollama**: Recommended for local, high-speed inference.
    - **OpenAI/Anthropic/Gemini**: Required for high-fidelity tactical analysis.
- **OSINT Sources**: API keys for Chaos, Netlas, Shodan, and SecurityTrails are recommended for the reconnaissance phase.

### 3. Integrated Security Tools (The Plugin Arsenal)
The core orchestrates a vast array of tools. Ensure these are available in your `PATH` or via the provided Docker images:
- **Discovery**: `amass`, `naabu`, `subfinder`.
- **Scanning**: `nuclei`, `nmap`, `rustscan`.
- **Exploitation**: `sqlmap`, `dalfox`, `commix`, `metasploit-framework`.
- **Cloud/Compliance**: `prowler`, `trivy`, `checkov`.

---

## 📚 Technical Documentation (Single Source of Truth)

All documentation is synchronized with the **V14.1 Sovereign Sync**:

*   [🔱 Sovereign Systems V14.1 Sync](redteam_rust_core/docs/SOVEREIGN_SYSTEMS.md): **Core Master Spec** for Layers 0-5.
*   [🏗️ V14 Core Architecture (Master)](redteam_rust_core/docs/V14_CORE_ARCHITECTURE.md): System topology and Swarm logic.
*   [🧠 AI Architecture Breakdown](redteam_rust_core/docs/AI_ARCHITECTURE.md): Deep Guide on tiered routing and token optimization.
*   [🎭 Adaptive Evasion: The Posture Manual](redteam_rust_core/docs/ADAPTIVE_EVASION.md): GHOST/STRIKE/BREACH posture transitions.

---

## 💻 Build & Deploy

```bash
# Clone the repository
git clone https://github.com/kripiman/OsintUltimate
cd OsintUltimate/redteam_rust_core

# Configure environment
cp .env.example .env
# Edit .env with your DIGITALOCEAN_TOKEN and AI keys

# Build for release
cargo build --release

# Run in autonomous mode
./target/release/redteam_rust_core --target example.com --autonomous --swarm
```

---

## 📜 Governance

> [!IMPORTANT]
> This platform is designed for authorized security testing only. All operations beyond passive reconnaissance require explicit authorization.
> The "Kill-Switch" (Ctrl+C) will automatically decommission all ephemeral infrastructure.

Private & Confidential - Sovereign Offensive Operations Only.
© 2026 RedTeam Lab | OsintUltimate V14.1 Protocol
