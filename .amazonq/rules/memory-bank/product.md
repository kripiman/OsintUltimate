# OsintUltimate — Product Overview

## Purpose
OsintUltimate (V14.1 "Sovereign Stealth Protocol") is a production-grade autonomous red team orchestration platform built in Rust. It performs multi-phase offensive security assessments — from passive OSINT through active exploitation and post-exploitation — under strict OPSEC constraints.

## Value Proposition
- Fully autonomous operation: single command drives recon → scan → exploit → persist → report
- Fail-closed egress: aborts instantly if stealth infrastructure (proxies/VPS) is compromised
- Multi-agent swarm with token-budget admission control to prevent starvation of critical tasks
- AttackGraph DFS pathfinding for automated AD escalation and lateral movement
- Integrated C2 sovereignty for persistent session maintenance

## Key Features
- **Adaptive Posture Management**: state-machine transitions between GHOST / STRIKE / BREACH based on target sensitivity
- **Sentinel Sovereign Orchestrator**: multi-phase waterfall discovery (Wayback → Chaos → Netlas → Shodan) with automatic fallback and API credit management
- **Swarm Mode** (`--swarm`): priority-aware multi-agent pool (Scout / Exploiter / C2 / Reporter roles) with atomic TokenBudget
- **Autonomous Mode** (`--autonomous`): full autopilot pipeline via `run_autopilot()`
- **MCP Server** (`--mcp-server`): Model Context Protocol SSE server for LLM tool integration
- **Real-time Dashboard** (`--dashboard <port>`): web UI with ed25519-signed JWT auth
- **Plugin System**: dynamic `.so` loading via `libloading`; plugins cover recon, exploitation, lateral movement, persistence, compliance, reporting
- **Stealth Infrastructure**: DigitalOcean ephemeral droplet pool with Shadowsocks/Hysteria (QUIC/UDP) proxy rotation; kill-switch on Ctrl-C destroys all droplets
- **Multi-Sink Output**: JSONL, SQLite, tactical C2 webhook (HTTPS-only, SSRF-safe)
- **Observability**: `tracing` + OpenTelemetry OTLP; optional JSON log mode; ActivityLog JSONL per event

## Target Users
- Authorized red team operators conducting penetration tests
- Security researchers performing vulnerability research on in-scope targets
- Purple team exercises requiring Blue Team detection tracking

## Use Cases
- Full-spectrum autonomous penetration test against a single host or bulk target list (`--input`)
- Stealth OSINT reconnaissance (GHOST posture, no active probes)
- Vulnerability validation with AI-assisted exploit generation
- Post-exploitation persistence and lateral movement in AD environments
- Compliance and reporting automation

## Governance
All Layer 4+ operations require explicit approval via the `ApprovalGate`. Platform is designed for **authorized security testing only**.
