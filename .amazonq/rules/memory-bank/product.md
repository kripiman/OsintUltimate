# Product Overview

## Purpose
OsintUltimate (v0.1.0 Sovereign) is an autonomous Red Team orchestration platform designed for offensive security operations. It operates as a multi-agent swarm system that performs reconnaissance, vulnerability assessment, and exploitation through a cognitive feedback loop with integrated AI decision-making.

## Value Proposition
- **Autonomous Operations**: Self-directed multi-agent swarm that decomposes targets into atomic tasks based on tactical cascade priority
- **AI-Powered Intelligence**: Tiered AI routing (Ollama/Phi for noise filtering, Claude/GPT-4/Kimi for tactical decisions) with CVSS-based exploit planning
- **Production-Grade Stealth**: Fail-closed egress policies, Docker proxy injection, ephemeral proxychains, and DNS-rebinding protection
- **Sovereign Data Control**: Lock-free PostgreSQL persistence with asynchronous enrichment to prevent I/O blocking during active operations
- **Zero Technical Debt**: Hardened through GHOST/STRIKE/BREACH audit cycles with memory bottlenecks and task leaks eradicated

## Key Features

### 4-Stage Sovereign Engine
1. **Liveness & Ingestion**: Strict DNS-rebinding protection filtering (is_safe_ip) - no private/local IPs scanned
2. **Planning (Swarm Orchestrator)**: Task decomposition via Tactical Cascade Priority (Passive Recon → Service Discovery → Active Enum → Exploitation)
3. **Cognition (AI Router)**: Multi-tier AI processing with Moka caching and Wenyan token optimization
4. **Execution (Isolated Pipeline)**: Docker-containerized execution of 60+ integrated security tools

### Arsenal Integration
- **Reconnaissance**: Subfinder, Amass, DNSx, Httpx, Nmap, Masscan
- **Web Security**: Nuclei, SQLmap, XSStrike, Nikto, Wappalyzer, GraphW00F
- **Cloud & Infrastructure**: ScoutSuite, Prowler, CloudMapper, Grype, Syft
- **Exploitation**: Metasploit, Ligolo, CrackQL, Schemathesis
- **Mobile**: APKTool, JADX, MobSF
- **Supply Chain**: Retire.js, Cosign verification

### Safety & Control
- **ApprovalGate**: Integrated approval mechanism for controlled offensive operations
- **Graceful Kill-Switch**: Ctrl+C triggers graceful shutdown with safe data flush to PostgreSQL
- **Sandbox Isolation**: All third-party tools execute in isolated Docker containers

## Target Users
- Red Team operators conducting authorized penetration testing
- Security researchers performing vulnerability assessments
- Bug bounty hunters requiring automated reconnaissance and exploitation workflows
- Enterprise security teams validating defensive posture

## Use Cases
- Autonomous reconnaissance and attack surface mapping
- Vulnerability discovery and exploitation with AI-guided prioritization
- Multi-target swarm operations with distributed task execution
- Continuous security monitoring via CertStream integration
- Supply chain security analysis and SBOM generation
- Cloud infrastructure security assessment (AWS, Azure, GCP)
