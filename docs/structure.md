# OsintUltimate V14.1 - Project Structure

## Root Directory Organization

```
OsintUltimate/
├── .amazonq/rules/memory-bank/     # AI assistant memory bank
├── .github/workflows/              # CI/CD automation
├── docs/                          # General documentation
├── prompts/                       # AI prompt templates
├── redteam_rust_core/            # Main Rust application
├── repo_readmes/                 # Reference documentation
├── scratch/                      # Development workspace
├── skills/                       # Capability definitions
└── README.md                     # Project overview
```

## Core Application Structure (redteam_rust_core/)

### Source Code Organization (`src/`)

#### Core Systems (`core/`)
- **ai/**: Multi-tiered LLM routing and AI orchestration
  - Provider integrations (OpenAI, Anthropic, Azure, Gemini, Ollama)
  - Context compression and token optimization
  - Router for adaptive decision-making
- **correlation/**: Active Directory ingestion and attack graph analysis
- **engine/**: Main application engine and orchestration
- **mcp/**: Model Context Protocol implementation
- **swarm/**: Multi-agent orchestration and token budgeting
- **validation/**: PoC validation and sovereign execution
- **waf/**: Web Application Firewall engine and policies
- **web/**: Web interface and API handlers

#### Infrastructure (`infrastructure/`)
- **decoy/**: Decoy infrastructure management
- **digital_ocean.rs**: Cloud provider integration
- **proxy.rs**: Proxy chain management and stealth networking

#### Data Models (`models/`)
- **constants.rs**: System-wide constants and configuration
- **findings.rs**: Vulnerability and finding data structures
- **scan_result.rs**: Scan result aggregation and storage

#### Plugin System (`plugins/`)
Organized by operational phase and capability:

- **reconnaissance/**: Intelligence gathering
  - `osint/`: Passive intelligence (Amass, Subfinder, Sovereign Recon)
  - `active/`: Active discovery (DNSx, HTTPx, Naabu)
  - `passive/`: Passive analysis (Wayback, GitLeaks, TruffleHog)

- **enumeration/**: Target enumeration
  - `network/`: Network scanning (Nmap, RustScan)
  - `web/`: Web application enumeration (Feroxbuster, FFUF, Katana)
  - `cloud/`: Cloud infrastructure enumeration (CloudBrute, Prowler)

- **intelligence/**: Vulnerability intelligence
  - `nuclei.rs`: Template-based vulnerability scanning
  - `jaeles.rs`: Web application security testing
  - `searchsploit.rs`: Exploit database integration

- **exploitation/**: Active exploitation
  - `web/`: Web application exploitation (SQLMap, Commix, Dalfox)
  - `network/`: Network exploitation (Impacket, NetExec, Hydra)
  - `mobile/`: Mobile application testing
  - `wireless/`: Wireless security testing

- **lateral_movement/**: Post-exploitation movement
  - `bloodhound.rs`: Active Directory analysis
  - `sliver.rs`: C2 framework integration
  - `ligolo.rs`: Network tunneling

- **persistence/**: Persistence establishment
  - `havoc.rs`: Advanced C2 framework integration

- **privilege_escalation/**: Privilege escalation
  - `certipy.rs`: Certificate-based escalation
  - `privesc_hunter.rs`: Automated privilege escalation

- **compliance/**: Security compliance scanning
  - `trivy.rs`: Container vulnerability scanning
  - `checkov.rs`: Infrastructure as Code scanning
  - `kubescape.rs`: Kubernetes security

- **verification/**: Manual verification tools
  - `burp.rs`: Burp Suite integration
  - `caido.rs`: Caido proxy integration
  - `zap.rs`: OWASP ZAP integration

- **reporting/**: Report generation and output

#### Utilities (`utils/`)
- **executor.rs**: Stealth command execution
- **proxy.rs**: Proxy management and validation
- **security.rs**: Security controls and OPSEC
- **telemetry.rs**: Monitoring and observability
- **hardware_detection.rs**: System capability detection
- **report_gen.rs**: Report generation utilities

## Architectural Patterns

### Multi-Agent Swarm Architecture
- **Orchestrator**: Central coordination and task distribution
- **Agent Pool**: Concurrent worker agents with role specialization
- **Token Budget**: Resource allocation and starvation prevention
- **Priority Queue**: Critical task prioritization

### Plugin-Based Extensibility
- **Modular Design**: Each tool as independent plugin
- **Trait-Based Interface**: Consistent plugin API
- **Dynamic Loading**: Runtime plugin discovery and loading
- **Capability Layers**: Phased operational capabilities (0-5)

### Stealth and OPSEC Integration
- **Proxy Wrapping**: All network traffic through proxy chains
- **Stealth Executor**: Sandboxed command execution
- **Approval Gates**: Human-in-the-loop controls
- **Fail-Closed Design**: Abort on security boundary violations

### Data Flow Architecture
- **Lock-Free Pipeline**: High-throughput data processing
- **Correlation Engine**: Attack graph construction and analysis
- **Persistence Layer**: SQLite-based result storage
- **Telemetry Sink**: Observability and monitoring

## Configuration and Deployment

### Docker Integration
- **Multi-stage builds**: Optimized container images
- **Tool isolation**: Containerized security tools
- **Compose orchestration**: Multi-service deployment

### Documentation Structure (`docs/`)
- **SOVEREIGN_SYSTEMS.md**: Core system specifications
- **V14_CORE_ARCHITECTURE.md**: Architectural overview
- **AI_ARCHITECTURE.md**: AI system design
- **SWARM_DYNAMICS.md**: Multi-agent coordination
- **ADAPTIVE_EVASION.md**: Stealth and evasion techniques
- **PLUGIN_DEVELOPMENT.md**: Plugin development guide