# OsintUltimate — Project Structure

## Repository Layout
```
OsintUltimate/
├── redteam_rust_core/       # Main Rust crate (binary + library)
│   ├── src/
│   │   ├── main.rs          # CLI entry point, Args parsing, engine bootstrap
│   │   ├── menu.rs          # Interactive TUI wizard (inquire)
│   │   ├── lib.rs           # Crate root, re-exports
│   │   ├── core/            # Engine internals
│   │   ├── infrastructure/  # External service clients
│   │   ├── models/          # Data types (Finding, TargetHost, etc.)
│   │   ├── plugins/         # Scanner plugin implementations
│   │   └── utils/           # Cross-cutting utilities
│   ├── Cargo.toml
│   ├── Dockerfile           # Alpine multi-stage build
│   ├── docker-compose.yml   # base / privileged / full profiles
│   └── docs/                # Architecture documentation
├── skills/                  # MITRE ATT&CK skill JSON files (T1190.json, etc.)
├── docs/                    # Project-level docs
├── prompts/                 # Audit/remediation prompt templates
└── repo_readmes/            # Reference READMEs from similar tools
```

## Core Module Breakdown (`src/core/`)
| Module | Responsibility |
|---|---|
| `engine/app.rs` | `RedTeamEngine` — top-level orchestration, pipeline/autopilot dispatch |
| `pipeline.rs` | 4-stage pipeline: Discovery → Liveness → Scanning → Sink |
| `orchestrator.rs` | Concurrent plugin execution via `JoinSet`, memory backpressure |
| `swarm/` | `SwarmOrchestrator` — multi-agent token-budgeted execution |
| `agent.rs` | `AutonomousAgent` — adaptive loop, PoC validation, AI decisions |
| `ai/` | Tiered LLM router, providers, compressor, token optimizer, scrubber |
| `correlation/` | `CorrelationEngine` + `AttackGraph` DFS, `AdIngestor` |
| `approval_gate.rs` | Risk-gated human-in-the-loop approval with audit log |
| `capability_layer.rs` | `ScanLayer` enum (Passive→PostExploitation), `ScanLayerPolicy` |
| `sandbox.rs` | `SandboxDispatcher` — Docker vs. FluidLocal tier selection |
| `sink.rs` | `DataSink` trait, `JsonlSink`, `SqliteSink`, `MultiSink`, `TimelineSink` |
| `lock_free_sink.rs` | `LockFreeResultSink` — `ArrayQueue`-backed batcher |
| `native_scanner.rs` | `IoUringScanner` — raw SYN packets via io-uring |
| `mcp/` | Model Context Protocol SSE server |
| `validation/` | `PocValidator` — AI-driven PoC generation and execution |
| `policy/` | `PolicyProvider` trait, `StaticPolicy`, RoE enforcement |
| `middleware.rs` | Command validation chain (TargetScope, FlagSafety, SafeCommand) |
| `factory.rs` | `EngineFactory` — hardware detection, AI router construction |
| `persistence.rs` | `PersistenceOrchestrator` — tactical plan generation |
| `waf/` | WAF detection and evasion strategies |
| `web/` | Real-time dashboard (axum) |

## Infrastructure (`src/infrastructure/`)
| Module | Responsibility |
|---|---|
| `proxy.rs` | `ProxyManager` — RT-Identity, fail-closed egress, managed exits |
| `digital_ocean.rs` | `DigitalOceanClient` — JIT droplet provisioning/destruction |
| `decoy/` | Decoy IP generation for nmap |

## Plugin Architecture (`src/plugins/`)
All plugins implement `ScannerPlugin` or `DiscoveryPlugin` traits. Organized by phase:
- `reconnaissance/` — osint, active (httpx, naabu, dnsx), passive (wayback, trufflehog, gitleaks)
- `enumeration/` — web (ffuf, nuclei, katana, nikto…), network (nmap, rustscan), cloud (pacu, cloudfox…)
- `exploitation/` — web (sqlmap, dalfox, commix, jwt_tool), network (hydra, netexec, responder, impacket)
- `lateral_movement/` — bloodhound, sliver, ligolo
- `persistence/` — havoc
- `privilege_escalation/` — certipy, privesc_hunter
- `intelligence/` — nuclei, jaeles, searchsploit
- `verification/` — zap, burp, caido
- `compliance/` — trivy, kubescape, checkov, osv_scanner
- `ffi.rs` — Ed25519-verified dynamic `.so` plugin loader

## Models (`src/models/`)
- `findings.rs` — `Finding`, `Severity`, `Category`, `Evidence`, `AIAnalysis`, `PocDefinition`
- `scan_result.rs` — `TargetHost`, `TargetStatus`, `TargetType`, `ScanMetadata`
- `objectives.rs` — `Objective`, `OPPLAN` with DFS cycle detection
- `engagement.rs` — `EngagementState` for mission persistence
- `constants.rs` — All `FINDING_*` and `PLUGIN_*` string constants

## Key Architectural Patterns
1. **Typestate pattern** — `StealthExecutor<GhostMode>` vs `StealthExecutor<BreachMode>` enforced at compile time
2. **RAII token guards** — `TokenGuard` auto-refunds on panic/drop
3. **Fail-closed networking** — `get_client_fail_closed()` returns `Err` if no proxy available
4. **Lock-free concurrency** — `crossbeam::ArrayQueue` for result ingestion, `DashMap` for shared state
5. **4-stage pipeline** — each stage communicates via bounded `mpsc` channels
