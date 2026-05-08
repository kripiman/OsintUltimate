# OsintUltimate - Project Structure

## Directory Organization
```
OsintUltimate/
├── .amazonq/rules/memory-bank/          # Memory bank documentation
├── .github/workflows/                   # CI/CD pipelines
├── assets/                              # Static assets (images, logos)
├── prompts/                             # AI prompt templates
├── redteam_rust_core/                   # Main Rust application
│   ├── bin/                            # Binary tools and utilities
│   ├── config/                         # Configuration files
│   ├── docker/                         # Docker configurations
│   ├── DOCS/                           # Technical documentation
│   ├── migrations/                     # Database migrations
│   ├── src/                            # Source code
│   │   ├── core/                       # Core engine components
│   │   ├── infrastructure/             # Infrastructure modules
│   │   ├── models/                     # Data models
│   │   ├── plugins/                    # Plugin system
│   │   └── utils/                      # Utility functions
│   ├── tools/                          # External security tools
│   ├── workspace/logs/                 # Log files
│   └── Cargo.toml                      # Rust dependencies
├── repo_readmes/                       # External repository documentation
├── scratch/                            # Temporary files
├── scripts/                            # Shell scripts
└── skills/                             # Skill definitions
```

## Core Components

### 1. Main Application (`redteam_rust_core/`)
- **Language**: Rust (2021 edition)
- **Architecture**: Async-first, high-performance red team engine
- **Build System**: Cargo with feature flags (bug-bounty, sovereign, mobile, ai-redteam)

### 2. Source Code Structure (`src/`)
- **`core/`**: Core engine components (orchestrator, AI router, MCP server)
- **`infrastructure/`**: Infrastructure modules (database, networking, caching)
- **`models/`**: Data models and schemas
- **`plugins/`**: Plugin system for tool integration
- **`utils/`**: Utility functions and helpers

### 3. Documentation (`DOCS/`)
- **`engine_core.md`**: 4-Stage architecture specification
- **`stealth_opsec.md`**: Stealth execution and OPSEC guidelines
- **`ai_infrastructure.md`**: AI tiered routing and token optimization
- **`swarm_intelligence.md`**: Multi-agent tactical roles
- **`plugins_and_tools.md`**: Complete arsenal of 60+ security tools

### 4. Infrastructure Components
- **Docker Integration**: Tool execution in isolated containers
- **PostgreSQL**: Primary data persistence
- **MCP Server**: Model Context Protocol integration
- **Async Runtime**: Tokio-based async execution

## Architectural Patterns

### 1. 4-Stage Sovereign Engine
```
Liveness & Ingestion → Planning → Cognition → Execution → Persistence
```

### 2. Multi-Agent Swarm Architecture
- **Scout Agents**: Passive reconnaissance and discovery
- **Planner Agents**: Task decomposition and prioritization
- **Exploiter Agents**: Active exploitation and vulnerability testing
- **AI Router**: Tiered AI system for decision-making

### 3. Plugin System
- **Docker-based Isolation**: Each tool runs in isolated containers
- **Standardized Interfaces**: Consistent plugin API
- **Tool Orchestration**: Parallel execution with resource management

### 4. Data Flow
```
Target Input → DNS Safety Check → Task Decomposition → AI Analysis → 
Tool Execution → Result Processing → PostgreSQL Storage → Reporting
```

## Key Files and Their Roles

### Configuration Files
- **`Cargo.toml`**: Rust dependencies and build configuration
- **`.env.oracle`**: Environment variables (API keys, tokens)
- **`docker-compose.yml`**: Docker orchestration
- **`config/programs.json.example`**: Tool configuration template

### Core Source Files
- **`src/main.rs`**: Application entry point and CLI interface
- **`src/core/orchestrator.rs`**: Main orchestration logic
- **`src/core/mcp/server.rs`**: MCP server implementation
- **`src/core/ai/token_optimizer.rs`**: AI token optimization
- **`src/lib.rs`**: Library exports and module organization

### Database
- **`migrations/`**: PostgreSQL schema migrations
- **Async Storage**: Lock-free PostgreSQL operations
- **Data Enrichment**: CVE data integration with findings

## Build Features
- **`bug-bounty`**: Default mode for normal operations
- **`sovereign`**: Full APT mode with C2/persistence capabilities
- **`mobile`**: Mobile security testing features
- **`ai-redteam`**: AI-powered red team operations

## Development Workflow
1. **Environment Setup**: Configure `.env.oracle` with API keys
2. **Build**: `cargo build --release` or `cargo build --features sovereign`
3. **Database**: Run PostgreSQL migrations
4. **Execution**: Run with target and autonomous flags
5. **Monitoring**: Check logs in `workspace/logs/`