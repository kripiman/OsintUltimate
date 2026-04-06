> ### Credits & Inspiration
> This project stands on the shoulders of giants. We credit and thank these projects for pioneering AI-powered offensive security:
>
> - [**PentestGPT**](https://github.com/GreyDGL/PentestGPT) — the OG that proved LLMs can pentest
> - [**PentAGI**](https://github.com/vxcontrol/pentagi) — fully autonomous agent architecture
> - [**Strix**](https://github.com/usestrix/strix) — AI hackers that find and fix vulns
> - [**CAI**](https://github.com/aliasrobotics/cai) — cybersecurity AI framework, 3600x faster than humans
> - [**HackingBuddyGPT**](https://github.com/ipa-lab/hackingBuddyGPT) — LLM hacking in 50 lines of code
> - [**Shannon**](https://github.com/KeygraphHQ/shannon) — white-box AI pentester
> - [**BlacksmithAI**](https://github.com/fr0gger/BlacksmithAI) — multi-agent pentest framework
> - [**PentestAgent**](https://github.com/GH05TCREW/pentestagent) — black-box AI security testing
> - [**Pentest Copilot**](https://github.com/bugbasesecurity/pentest-copilot) — AI-driven pentest agent
>
> Their open-source contributions made tools like this possible.

> **Legal Disclaimer:** Pentest Swarm AI is designed exclusively for **authorized security testing**, **bug bounty programs**, **CTF competitions**, and **educational research**. You must obtain explicit written permission from the target system owner before running any scan. Unauthorized access to computer systems is illegal under the Computer Fraud and Abuse Act (CFAA), the Computer Misuse Act, and equivalent laws worldwide. The authors and contributors of this project accept **no liability** for misuse, damage, or any illegal activity conducted with this tool. By using this software, you agree that you are solely responsible for ensuring your use complies with all applicable laws and regulations. **Do not use this tool against systems you do not own or have explicit authorization to test.**

<p align="center">
  <img src="banner/pentest-swarm-ai-banner.gif?v=3" alt="Pentest Swarm AI" width="800">
</p>

<p align="center">
  <h1 align="center">Pentest Swarm AI</h1>
  <p align="center">
    <strong>Unleash a swarm of AI agents to autonomously pentest your software</strong>
  </p>
  <p align="center">
    <a href="#quick-start">Quick Start</a> &middot;
    <a href="#how-the-swarm-works">How It Works</a> &middot;
    <a href="#features">Features</a> &middot;
    <a href="PLAN.md">Architecture</a> &middot;
    <a href="#contributing">Contributing</a>
  </p>
</p>

<p align="center">
  <img src="https://img.shields.io/github/stars/Armur-Ai/Pentest-Swarm-AI?style=for-the-badge&color=f59e0b" alt="Stars">
  <img src="https://img.shields.io/badge/Go-1.24-00ADD8?style=for-the-badge&logo=go" alt="Go">
  <img src="https://img.shields.io/badge/License-Apache%202.0-blue?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/badge/AI-Claude%20%7C%20Ollama-purple?style=for-the-badge" alt="AI">
</p>

---

**Pentest Swarm AI** is a Go-native platform that deploys a coordinated swarm of specialist AI agents to autonomously perform full-cycle penetration tests. Each agent is purpose-built for a specific phase — recon, classification, exploitation, reporting — and the swarm orchestrator coordinates them in real-time using a ReAct reasoning loop.

One command. One API key. A full pentest report.

```bash
export PENTESTSWARM_ORCHESTRATOR_API_KEY=sk-ant-your-key-here
pentestswarm scan target.com --scope target.com
```

---

## Quick Start

```bash
# Install (pick one)
brew install armur-ai/tap/pentestswarm           # macOS
curl -sSL https://install.pentestswarm.ai | sh    # Linux
docker compose -f deploy/docker-compose.yml up     # Docker
go install github.com/Armur-Ai/Pentest-Swarm-AI/cmd/pentestswarm@latest  # Go

# Set your Claude API key (that's the only config needed)
export PENTESTSWARM_ORCHESTRATOR_API_KEY=sk-ant-your-key-here

# Launch the swarm
pentestswarm scan example.com --scope example.com --follow
```

No Ollama. No model downloads. No GPU. Just a Claude API key and you're pentesting.

---

## How the Swarm Works

```
                        YOU
                         |
                  pentestswarm scan target.com
                         |
              ┌──────────▼──────────┐
              │   SWARM ORCHESTRATOR │
              │   (ReAct Loop)       │
              │   Plans · Adapts ·   │
              │   Coordinates        │
              └──┬───┬───┬───┬──────┘
                 │   │   │   │
        ┌────────┘   │   │   └────────┐
        ▼            ▼   ▼            ▼
   ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐
   │  RECON  │ │CLASSIFY │ │ EXPLOIT │ │ REPORT  │
   │  AGENT  │ │  AGENT  │ │  AGENT  │ │  AGENT  │
   │         │ │         │ │         │ │         │
   │subfinder│ │CVE map  │ │Attack   │ │PDF/HTML │
   │httpx    │ │CVSS 3.1 │ │chains   │ │Markdown │
   │nuclei   │ │FP filter│ │MITRE    │ │JSON     │
   │naabu    │ │severity │ │ATT&CK   │ │exec     │
   │katana   │ │ranking  │ │dry-run  │ │summary  │
   │dnsx/gau │ │         │ │cleanup  │ │         │
   └─────────┘ └─────────┘ └─────────┘ └─────────┘
```

The swarm orchestrator **thinks, plans, and adapts** in real-time:

1. Deploys the **Recon Agent** — runs 7 security tools natively in Go, builds a structured attack surface
2. Sends findings to the **Classifier Agent** — maps CVEs, scores CVSS v3.1, filters false positives
3. The **Exploit Agent** constructs multi-step attack chains with chain-of-thought reasoning
4. Orchestrator executes steps, adapts the plan based on results, pivots when paths fail
5. The **Report Agent** generates a professional pentest report (PDF/HTML/Markdown)

Every tool execution is scope-validated. Every exploitation step has a registered cleanup command. Emergency stop kills the swarm in under 5 seconds.

---

## Features

### The Swarm
- **5-agent architecture** — Orchestrator + 4 specialists, each purpose-built
- **7 native Go security tools** — subfinder, httpx, nuclei, naabu, katana, dnsx, gau (no subprocess overhead)
- **ReAct orchestration** — reason, act, observe, adapt in real-time
- **CVSS v3.1 scoring** — exact FIRST specification with context adjustment
- **Scope enforcement** — hard-coded on every command, no exceptions
- **Campaign state machine** — full lifecycle with emergency stop

### Modes
| Mode | What it does |
|------|-------------|
| `--mode manual` | Full autonomous pentest with human oversight |
| `--mode bugbounty` | Imports H1/Bugcrowd scope, deduplicates, formats program-compliant reports |
| `--mode asm` | Continuous attack surface monitoring, auto-triggers on new assets |
| `--mode ctf` | Autonomous HackTheBox/TryHackMe machine solving |

### Integrations
- **MCP Server** — `pentestswarm mcp serve` exposes the swarm to Claude Desktop, Cursor, any MCP client
- **VS Code Extension** — findings inline in your IDE, scan from command palette
- **GitHub Action** — SARIF output, findings in GitHub Security tab, fail PRs on critical vulns
- **Jira** — auto-create issues with severity-mapped priorities
- **Slack** — real-time alerts, thread-per-campaign, daily digest
- **SIEM** — CEF, STIX 2.1, SARIF output for ArcSight/Splunk/QRadar
- **Webhooks** — HMAC-signed event delivery with retry

### Ecosystem
- **Community Playbooks** — YAML attack playbooks (like nuclei-templates but for full attack chains)
- **Agent Memory** — the swarm gets smarter with every scan
- **Shared Intelligence** — opt-in anonymized pattern sharing across installations
- **Plugin System** — custom tools, report templates, and playbooks

### Dashboard & TUI
- **Next.js 15 dashboard** — dark theme, live attack surface graph, agent activity monitor, attack path DAG, real-time metrics
- **Terminal TUI** — multi-panel view showing all agents working simultaneously, attack paths, findings histogram
- **Interactive Explorer** — browse the attack surface in your terminal with search and filter

---

## CLI

```bash
pentestswarm scan <target> --scope <scope>     # Launch the swarm
pentestswarm campaign watch <id>                # Live TUI — watch agents work
pentestswarm campaign explore <id>              # Browse attack surface interactively
pentestswarm explain <finding-id>               # Explain in plain English
pentestswarm doctor                             # 8-point system health check
pentestswarm serve                              # Start API server + dashboard
pentestswarm mcp serve                          # MCP server for Claude/Cursor
pentestswarm ctf solve <target>                 # Autonomous CTF solving
pentestswarm playbook run <name>                # Run a community playbook
```

---

## LLM Providers

All agents inherit from a single provider config. Set one key, the entire swarm works.

| Provider | Setup | Privacy | Best for |
|----------|-------|---------|----------|
| **Claude** (default) | `export PENTESTSWARM_ORCHESTRATOR_API_KEY=...` | Cloud | Best quality, zero setup |
| **Ollama** | Install Ollama + pull models | 100% local | Full privacy, air-gapped |
| **LM Studio** | Load model, enable server | 100% local | GUI model management |

---

## Tech Stack

| Component | Technology | Why |
|-----------|-----------|-----|
| Platform | **Go 1.24** | Single binary, goroutine concurrency, native security tools |
| CLI | **Cobra + bubbletea** | Beautiful TUI with multi-panel agent view |
| LLM | **Claude API / Ollama / LM Studio** | Best quality cloud + full privacy local |
| Security Tools | **subfinder, httpx, nuclei, naabu, katana, dnsx, gau** | Native Go libraries, no subprocess |
| API | **Fiber** (fasthttp) | High-performance HTTP |
| Database | **PostgreSQL 16 + pgvector** | Campaign history + semantic search |
| Cache | **Redis 7** | Rate limiting, session state |
| Dashboard | **Next.js 15 + shadcn/ui + tremor** | Dark-first, chart-heavy, enterprise-grade |
| MCP | **JSON-RPC stdio** | Claude Desktop + Cursor integration |

---

## Development

```bash
git clone https://github.com/Armur-Ai/Pentest-Swarm-AI.git
cd Pentest-Swarm-AI
./scripts/setup.sh    # Install tools, start Postgres/Redis/Ollama
make build            # Compile binary
make test             # Run tests (24 passing)
make dev              # Hot-reload development
```

---

## Why "Swarm"?

Traditional pentesting tools run one scan at a time. Pentest Swarm AI deploys **multiple specialist agents working in parallel** — each one an expert at its job — coordinated by an orchestrator that thinks, adapts, and makes strategic decisions. Like a swarm, each agent is simple but the collective intelligence is powerful.

The swarm learns from every engagement. Each scan makes the next one smarter. Community playbooks compound the knowledge. The shared intelligence network means every user benefits from every other user's scans.

**One agent is a tool. A swarm is a platform.**

---

## License

Apache 2.0 — see [LICENSE](LICENSE).

Built by [Armur AI](https://github.com/Armur-Ai).
