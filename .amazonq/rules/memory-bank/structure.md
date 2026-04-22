# OsintUltimate — Project Structure

## Repository Layout

```
OsintUltimate/
├── redteam_rust_core/       # Main Rust crate (the entire engine)
│   ├── src/
│   │   ├── main.rs          # CLI entrypoint, Args (clap), engine wiring
│   │   ├── menu.rs          # Interactive TUI menu (inquire)
│   │   ├── lib.rs           # Crate root, re-exports
│   │   ├── core/            # Engine internals
│   │   ├── models/          # Shared data types
│   │   ├── plugins/         # Offensive capability plugins
│   │   ├── infrastructure/  # Cloud/proxy provisioning
│   │   └── utils/           # Cross-cutting utilities
│   ├── Cargo.toml
│   ├── Dockerfile / docker-compose.yml
│   └── docs/                # Technical specs (SOVEREIGN_SYSTEMS, V14_CORE_ARCHITECTURE, …)
├── docs/                    # Project-level docs, roadmaps, comparative analyses
├── prompts/                 # LLM audit/remediation prompt templates
├── repo_readmes/            # Reference READMEs from comparable tools
├── triage_automation/       # Standalone triage scripts/utils
├── skills/                  # Tactical knowledge base (MITRE techniques)
├── scratch/                 # Throwaway experiments
├── .amazonq/rules/memory-bank/  # This Memory Bank
├── CLAUDE.md                # AI assistant context/instructions
├── MEMORIA.md               # Running project memory/decisions log
└── HANDOFF.md               # Handoff notes between sessions
```

## Core Module Breakdown (`src/core/`)

| Module | Responsibility |
|---|---|
| `engine/` | `RedTeamEngine` — top-level orchestrator; `EngineConfig`; `run_pipeline()` / `run_autopilot()` |
| `factory.rs` | `EngineFactory` — hardware detection, infrastructure limit calculation |
| `pipeline.rs` | Sequential scan pipeline; layer-gated execution |
| `orchestrator.rs` | Sentinel Sovereign Orchestrator; waterfall discovery loop |
| `swarm/` | `SwarmOrchestrator`, `TokenBudget` admission control, agent role dispatch |
| `ai/` | Multi-provider LLM routing (Ollama, OpenAI, Anthropic, Azure, Gemini); token optimizer; context compressor; scrubber |
| `mcp/` | MCP SSE server; protocol types; input sanitizer |
| `agent.rs` | Individual agent task execution |
| `approval_gate.rs` | Human-in-the-loop gate for Layer 4+ operations |
| `capability_layer.rs` | `ScanLayer` enum (Passive → PostExploitation) |
| `sandbox.rs` | `SandboxDispatcher` — Docker + FluidLocal process isolation |
| `sink.rs` | `MultiSink`, `JsonlSink`, `SqliteSink`, `TacticalWebhookSink` |
| `lock_free_sink.rs` | Lock-free telemetry ingestion (io-uring backed) |
| `persistence.rs` | Post-exploit persistence orchestration |
| `c2.rs` | C2 session management |
| `correlation/` | `AttackGraph` DFS; AD ingestor |
| `policy/` | `PolicyProvider`, `StaticPolicy` — PSL + regex scope enforcement, RoE |
| `validation/` | PoC executor, exploit generator, sovereign validator |
| `waf/` | WAF detection engine and evasion profiles |
| `web/` | Axum dashboard server; embedded assets; ed25519 JWT auth |
| `filter.rs` | Output deduplication and noise filtering |
| `middleware.rs` | Request middleware (jitter, rate limiting) |
| `plugin_loader.rs` | Dynamic `.so` plugin loading via `libloading` |
| `blackarch.rs` | BlackArch tool catalogue integration |
| `native_scanner.rs` | Built-in port/service scanner (smoltcp / io-uring) |
| `source_analyzer.rs` | Source code analysis capabilities |
| `resource_manager.rs` | Memory and CPU resource tracking |

## Plugin Categories (`src/plugins/`)

```
reconnaissance/
  ├── active/    — dnsx, httpx, naabu
  ├── osint/     — amass, subfinder, uncover, sovereign_recon
  └── passive/   — gitleaks, trufflehog, wayback
enumeration/
  ├── network/   — nmap (with parser), rustscan
  ├── web/       — ffuf, feroxbuster, katana, nikto, gowitness, …
  └── cloud/     — cloudbrute, cloudfox, pacu, prowler, kubebench
exploitation/
  ├── web/       — sqlmap, dalfox, commix, jwt_tool, wapiti
  └── network/   — hydra, impacket, netexec, responder, coercer
intelligence/   — nuclei, jaeles, searchsploit
lateral_movement/ — bloodhound, sliver, ligolo
privilege_escalation/ — certipy, privesc_hunter
persistence/    — havoc
compliance/     — trivy, checkov, kubescape, osv_scanner
verification/   — burp, caido, zap, poc
reporting/      — bug_bounty
```

## Models (`src/models/`)

- `findings.rs` — `Finding` struct (cvss_score, mitre_attack, evidence, severity)
- `scan_result.rs` — `ScanResult`, `TargetHost`, `TargetStatus`, `TargetType`
- `objectives.rs` — Objective tracking types
- `constants.rs` — Shared constants

## Infrastructure (`src/infrastructure/`)

- `digital_ocean.rs` — Ephemeral droplet provisioning, destroy-all kill-switch
- `proxy.rs` — Proxy pool management, rotation logic
- `decoy/` — Decoy traffic generation and control

## Utils (`src/utils/`)

| File | Purpose |
|---|---|
| `config.rs` | `Config::from_env()` — all env-var configuration |
| `telemetry.rs` | OTel init/shutdown, tracing subscriber setup |
| `activity_log.rs` | JSONL event log per engagement |
| `report_gen.rs` | HTML report generation from JSONL via Handlebars |
| `executor.rs` | Async subprocess execution with timeout/kill |
| `sandbox.rs` | Metacharacter sanitization for shell commands |
| `proxy.rs` | SOCKS5 proxy client helpers |
| `jitter.rs` | Randomized delay distributions for OPSEC |
| `stealth_http.rs` | Stealth HTTP client (UA pinning, header normalization) |
| `cvss.rs` | CVSS score calculation |
| `cve_cache.rs` | Local CVE data cache |
| `deduplication.rs` | Bloom-filter-based finding deduplication |
| `hardware_detection.rs` | CPU/RAM profiling for auto-concurrency |
| `memory_monitor.rs` | Runtime memory limit enforcement |
| `tool_detection.rs` | Checks which external tools are installed |
| `security.rs` | SSRF-safe host validation, input sanitization |

## Architectural Patterns

1. **Layer-gated execution**: `ScanLayer` enum gates which plugins run; `--max-layer` CLI flag controls depth.
2. **Sink abstraction**: all findings flow through `DataSink` trait → `MultiSink` fan-out.
3. **Fail-closed egress**: proxy liveness checked before any active operation; aborts on failure.
4. **Token budget**: `TokenBudget` (atomic) shared across swarm agents; critical roles get reserved quota.
5. **Plugin trait**: all plugins implement a common async trait; loaded statically or dynamically via FFI.
6. **ApprovalGate**: async channel-based human confirmation required before exploitation layers.
