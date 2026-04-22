# OsintUltimate — Product Overview

## Purpose
OsintUltimate (V14.1 "Sovereign Stealth Protocol") is a production-grade autonomous red team orchestration platform built in Rust. It automates the full offensive security lifecycle — from passive OSINT through active exploitation, post-exploitation, and C2 persistence — under a strict "No-Proxy, No-Traffic" fail-closed egress policy.

## Value Proposition
- **Autonomous Operation**: Multi-agent swarm (Scout, Exploiter, C2-Operator, Planner, GhostReporter) that self-directs through the attack lifecycle without constant human input.
- **Sovereign OPSEC**: Every network packet is routed through a managed SOCKS5/Shadowsocks/Hysteria egress layer; direct IP exposure is architecturally impossible in stealth mode.
- **AI-Augmented Decision Making**: Tiered LLM routing (Ollama local → Gemini Flash/GPT-4o-mini → Gemini Pro/Claude 3.5) with token-budget admission control and Wenyan-Ultra compression.
- **Plugin Ecosystem**: 60+ scanner plugins covering recon, enumeration, exploitation, lateral movement, persistence, compliance, and verification.

## Key Features
| Feature | Description |
|---|---|
| Adaptive Posture Management | State-machine: GHOST → STRIKE → BREACH based on detection feedback |
| Fail-Closed Egress | `ProxyManager::get_client_fail_closed()` — aborts if no healthy proxy |
| AttackGraph Correlation | DFS-based pathfinding; auto-identifies AD Path-to-DA |
| Token Budget Admission | Priority-aware `TokenBudget` prevents AI cost runaway |
| io-uring Native Scanner | Zero-copy SYN packet dispatch for high-throughput port scanning |
| Lock-Free Sink | `SegQueue`-backed result pipeline; SQLite WAL + JSONL streaming |
| Dynamic Plugin Loading | Ed25519-signed `.so`/`.dylib` plugins with ABI version enforcement |
| MCP Server | Model Context Protocol SSE server for IDE/agent integration |
| Dashboard | Real-time web UI with Ed25519-signed JWT auth |
| DigitalOcean Autonomous Egress | JIT droplet provisioning with auto-destruction kill-switch |

## Target Users
- **Red Team Operators**: Authorized penetration testers running full-lifecycle engagements.
- **Bug Bounty Hunters**: Automated recon and vulnerability discovery pipelines.
- **Security Researchers**: Extensible platform for custom scanner plugin development.

## Use Cases
1. **Autonomous Engagement**: `--autonomous` flag activates Sentinel agent; runs discovery → scanning → PoC validation → C2 deployment without intervention.
2. **Swarm Mode**: `--swarm` distributes work across specialized AI agents with token budgeting.
3. **Passive OSINT Only**: `--max-layer passive` restricts to zero-traffic certificate transparency, Wayback, Chaos, Netlas, Shodan queries.
4. **Compliance Audit**: Trivy, Kubescape, Checkov, OSV Scanner plugins for infrastructure hardening.
5. **AD Enumeration**: BloodHound + AdIngestor + CorrelationEngine for automated Path-to-DA discovery.

## Governance
All Layer 4+ (Exploitation) and Layer 5 (Post-Exploitation) operations require explicit approval via `ApprovalGate`. Risk score ≥ 70 triggers a mandatory human-in-the-loop halt ("Sovereign Handover").
