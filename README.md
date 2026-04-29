<p align="center">
  <img src="mimicry_logo.png" width="200" alt="OsintUltimate Mimicry Octopus">
</p>

# 🔱 OsintUltimate (v0.1.0 Sovereign)

> **Autonomous Red Team Orchestration & Sovereign Offensive Operations**
> 
> *Binary Precision. Fail-Closed Egress. Sovereign Command.*
> *V15 Protocol: Adaptive Posture Management, Priority Swarm Dynamics, and PostgreSQL Data Sovereignty.*

---

## ✅ Production Readiness Status: **SEALED & HARDENED (100/100)**
**OsintUltimate v0.1.0** has passed the full **GHOST/STRIKE/BREACH** audit cycle for Oracle ARM Cloud infrastructure.
- **Zero Technical Debt**: Memory bottlenecks (Arc clones) and Task Leaks completely eradicated.
- **Hardened Egress**: Production-ready stealth infrastructure with autonomous Docker Proxy injection (`ALL_PROXY`) and ephemeral proxychains.
- **Safety**: Integrated `ApprovalGate` and `Graceful Kill-Switch` for controlled, data-safe offensive operations.

---

## ⚙️ How It Works (The 4-Stage Sovereign Engine)

OsintUltimate is not a simple scanner; it is an **Autonomous Multi-Agent Swarm** that operates through a cognitive feedback loop:

1.  **Liveness & Ingestion**: The system filters targets through strict DNS-rebinding protection (`is_safe_ip`). No private or local IP is ever scanned.
2.  **Planning (Swarm Orchestrator)**: The system decomposes a target into atomic tasks based on the **Tactical Cascade Priority** (Passive Recon -> Service Discovery -> Active Enum -> Exploitation).
3.  **Cognition (AI Router)**: Every finding is processed by a tiered AI system. 
    - *Tier 0 (Ollama/Phi)* handles high-volume noise filtering.
    - *Tier 1/2 (Claude Code / Kimi K2.6 / GPT-4)* perform complex tactical decision-making and exploit planning based on CVSS scoring.
4.  **Execution (Isolated Pipeline)**: Tasks are executed via isolated Docker containers leveraging over 60+ integrated industry tools (Nmap, Subfinder, Sqlmap, Ligolo, etc.).
5.  **Sovereign Persistence (Lock-Free)**: Findings are enriched with CVE data and stored asynchronously in **PostgreSQL** to prevent I/O blocking during active strikes.

---

## 🛠️ Dependencies & Requirements

To operate at its full "Sovereign" potential, the following components are required:

### 1. System Dependencies
- **Rust (Stable)**: Core engine build and execution.
- **Docker**: Essential for running third-party security tools (Plugins) in isolated environments.
- **PostgreSQL**: Robust persistence for findings and state tracking.
- **OpenSSL / Libssl-dev**: Required for encrypted communications.

### 2. Infrastructure & API Keys (Configured via `.env.oracle`)
- **DigitalOcean Token**: Mandatory for the **Stealth VPS** rotation.
- **AI Backend**:
    - **Ollama**: Recommended for local, high-speed inference.
    - **Claude CLI / Kimi / OpenAI**: Required for high-fidelity tactical analysis.
- **OSINT Sources**: API keys for Chaos, Netlas, Shodan, etc.

### 3. Integrated Security Tools (The Arsenal)
The core orchestrates a massive array of over 60 tools (Recon, Web Fuzzing, Cloud Enum, Active Directory, C2). 
👉 **[View the Complete Arsenal Breakdown](redteam_rust_core/DOCS/plugins_and_tools.md)**

---

## 📚 Technical Documentation (Single Source of Truth)

All documentation is synchronized and represents the exact state of the compiled binary:

*   [⚙️ Engine Core: El Pipeline Soberano](redteam_rust_core/DOCS/engine_core.md): Core Master Spec for the 4-Stage Architecture.
*   [🛡️ Sigilo e Infraestructura (OPSEC)](redteam_rust_core/DOCS/stealth_opsec.md): Stealth execution, Fail-Closed policies, and Docker Sandboxing.
*   [🧠 Infraestructura IA & Prompt Engineering](redteam_rust_core/DOCS/ai_infrastructure.md): Deep Guide on Tiered Routing, Moka Cache, and Wenyan Token optimization.
*   [🐝 Swarm & Multi-Agent Intelligence](redteam_rust_core/DOCS/swarm_intelligence.md): Tactical roles (Scout, Planner, Exploiter) and Token Budgeting.
*   [🧰 Arsenal de Herramientas y Plugins](redteam_rust_core/DOCS/plugins_and_tools.md): Complete list of all integrated tools and their tactical priority.
*   [🕵️ Reporte de Auditoría Sistémica V14](redteam_rust_core/DOCS/SYSTEMIC_AUDIT_V14.md): The official security audit sealing the core.

---

## 💻 Build & Deploy

```bash
# Clone the repository
git clone https://github.com/kripiman/OsintUltimate
cd OsintUltimate/redteam_rust_core

# Configure environment
cp ../.env.example ../.env.oracle
# Edit .env.oracle with your DIGITALOCEAN_TOKEN and AI keys

# Build for release
cargo build --release

# Run in autonomous mode targeting PostgreSQL
./target/release/redteam_rust_core --target example.com --autonomous --swarm --postgres-url "postgres://user:pass@localhost:5432/osintdb"
```

---

## 📜 Governance

> [!CAUTION]
> This platform is designed for authorized security testing only. All operations beyond passive reconnaissance require explicit authorization.
> The **Kill-Switch (Ctrl+C)** utilizes Graceful Shutdown tokens to immediately stop all Docker containers and flush data to Postgres safely.

Private & Confidential - Sovereign Offensive Operations Only.
© 2026 RedTeam Lab | OsintUltimate v0.1.0 Protocol
