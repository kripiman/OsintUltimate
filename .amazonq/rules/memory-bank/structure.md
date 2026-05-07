# Project Structure

## Directory Organization

### Root Level
```
OsintUltimate/
├── redteam_rust_core/          # Main Rust application
├── assets/                      # Visual assets (logos, images)
├── prompts/                     # AI audit and documentation prompts
├── repo_readmes/                # Reference documentation from similar projects
├── scripts/                     # Deployment and utility scripts
├── skills/                      # MITRE ATT&CK technique definitions
├── .env.oracle                  # Production environment configuration
└── README.md                    # Project documentation
```

### Core Application (`redteam_rust_core/`)
```
redteam_rust_core/
├── src/                         # Source code
│   ├── core/                    # Core engine components
│   ├── infrastructure/          # Cloud and proxy infrastructure
│   ├── models/                  # Data models and types
│   ├── plugins/                 # Security tool plugins
│   ├── utils/                   # Utility modules
│   ├── main.rs                  # Application entry point
│   ├── lib.rs                   # Library exports
│   └── menu.rs                  # Interactive CLI menu
├── DOCS/                        # Technical documentation
├── tools/                       # Embedded security tools (graphw00f, crackql)
├── bin/                         # Binary executables and tools
├── docker/                      # Docker configurations
├── migrations/                  # PostgreSQL schema migrations
├── workspace/                   # Runtime workspace (logs, outputs)
├── Cargo.toml                   # Rust dependencies
├── package.json                 # Node.js dependencies (retire.js)
└── docker-compose.yml           # Container orchestration
```

## Core Components

### `src/core/` - Engine Architecture
- **agent.rs**: Agent behavior and task execution
- **orchestrator.rs**: Multi-agent swarm coordination
- **pipeline.rs**: 4-stage processing pipeline
- **sink.rs / lock_free_sink.rs**: Lock-free data persistence
- **sandbox.rs**: Docker container isolation
- **approval_gate.rs**: Safety approval mechanism
- **resource_manager.rs**: Memory and CPU management
- **ai/**: AI routing and prompt engineering
- **swarm/**: Multi-agent coordination logic
- **engine/**: Core execution engine
- **policy/**: Security policies and rules
- **validation/**: Input validation and safety checks
- **web/**: Web interface and API

### `src/infrastructure/` - Cloud & Networking
- **proxy.rs**: Proxy rotation and management
- **digital_ocean.rs**: VPS provisioning and rotation
- **certstream.rs**: Certificate transparency monitoring
- **decoy/**: Decoy infrastructure for stealth

### `src/models/` - Data Structures
- **findings.rs**: Security finding models
- **scan_result.rs**: Scan result aggregation
- **engagement.rs**: Engagement tracking
- **objectives.rs**: Mission objectives and goals
- **constants.rs**: System-wide constants

### `src/plugins/` - Security Modules
- **reconnaissance/**: Passive and active recon
- **enumeration/**: Service and endpoint enumeration
- **exploitation/**: Vulnerability exploitation
- **intelligence/**: Threat intelligence gathering
- **lateral_movement/**: Network traversal
- **privilege_escalation/**: Privilege escalation techniques
- **persistence/**: Persistence mechanisms
- **detection_evasion/**: Evasion techniques
- **compliance/**: Compliance checking
- **verification/**: Result verification
- **reporting/**: Report generation

### `src/utils/` - Utilities
- **executor.rs**: Command execution wrapper
- **liveness.rs**: Target liveness checking
- **security.rs**: Security utilities (is_safe_ip)
- **stealth_http.rs**: Stealth HTTP client
- **cve_cache.rs**: CVE database caching
- **cvss.rs**: CVSS scoring
- **telemetry.rs**: OpenTelemetry integration
- **report_gen.rs**: Report generation
- **deduplication.rs**: Finding deduplication

## Architectural Patterns

### Multi-Agent Swarm
- Orchestrator coordinates multiple specialized agents (Scout, Planner, Exploiter)
- Task decomposition based on Tactical Cascade Priority
- Token budgeting for AI operations
- Distributed task queue with PostgreSQL backing

### Async-First Design
- Tokio runtime for all I/O operations
- Lock-free data structures (DashMap, lock_free_sink)
- Async streams for real-time processing
- Non-blocking persistence layer

### Plugin Architecture
- Modular plugin system for security tools
- Docker-based isolation for third-party tools
- FFI support for native integrations
- Dynamic plugin loading

### Tiered AI Routing
- Tier 0: Ollama/Phi for high-volume filtering
- Tier 1/2: Claude/GPT-4/Kimi for tactical decisions
- Moka cache for prompt deduplication
- Wenyan token optimization

### Fail-Closed Security
- DNS-rebinding protection (is_safe_ip)
- Approval gates for destructive operations
- Graceful shutdown with data preservation
- Audit logging for all operations

## Data Flow
1. Target ingestion → Liveness validation → Safe IP check
2. Orchestrator → Task decomposition → Priority assignment
3. Agent selection → Docker sandbox → Tool execution
4. Output capture → AI analysis → Finding enrichment
5. CVE correlation → CVSS scoring → PostgreSQL persistence
6. Report generation → Export (JSON/HTML/PDF)
