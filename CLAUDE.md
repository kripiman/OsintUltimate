# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Mimikri RedTeam Core** — High-performance async-first red team assessment engine supporting multiple target types (web, network, mobile, cloud, container) with 70+ built-in plugins, distributed worker mode, and AI-powered autonomous assessment.

## Build & Test Commands

```bash
# Build
cargo build --package redteam_rust_core

# Build release (optimized)
cargo build --release --package redteam_rust_core

# Run tests
cargo test --package redteam_rust_core

# Run single test
cargo test --package redteam_rust_core test_name -- --nocapture

# Lint & warnings
cargo clippy --package redteam_rust_core -- -D warnings

# Format check
cargo fmt --package redteam_rust_core -- --check

# Check type safety (SQLx compile-time checking)
cargo sqlx prepare --check

# Generate HTML coverage report
cargo tarpaulin --package redteam_rust_core --out Html
```

## Architecture Overview

### High-Level Design

```
┌─────────────────────────────────────────────────────────────┐
│                       CLI Entry (main.rs)                    │
│  - Parse args, init telemetry, setup stealth infrastructure │
│  - Dashboard, CertStream daemon, worker mode routing        │
└─────────────────────────┬───────────────────────────────────┘
                          │
           ┌──────────────┴──────────────┐
           │                             │
    ┌──────▼──────┐          ┌───────────▼────────┐
    │  Orchestrator         │  Pipeline          │
    │  (Multi-agent swarm   │  (Sequential layer │
    │   V4.0 mode)          │   processing)      │
    └──────┬──────┘          └───────────┬────────┘
           │                             │
     ┌─────▼─────────────────────────────▼──────┐
     │      Plugin Registry (70+ plugins)        │
     │  ┌──────────────────────────────────────┐ │
     │  │ Reconnaissance  │ Enumeration        │ │
     │  │ Exploitation    │ Verification       │ │
     │  │ Post-Expl       │ Intelligence       │ │
     │  │ Detection Evasion Lateral Movement   │ │
     │  └──────────────────────────────────────┘ │
     └──────────────┬──────────────────────────┘
                    │
      ┌─────────────▼─────────────┐
      │  Reactive Engine (V16.1)  │
      │  - Attack graph chains    │
      │  - Automated discovery    │
      │  - Depth limit: 5         │
      │  - ReactiveEngine API     │
      └─────────────┬─────────────┘
                    │
      ┌─────────────▼─────────────────────────┐
      │    Multi-Sink Output                  │
      │  ┌─────────────────────────────────┐  │
      │  │ JSONL │ PostgreSQL │ Webhooks  │  │
      │  │ Discord │ NATS Mesh │ Timeline │  │
      │  │ Bug Bounty Auto-Submit         │  │
      │  └─────────────────────────────────┘  │
      └───────────────────────────────────────┘
```

### Core Module Organization

- **`core/engine.rs`** — Main `RedTeamEngine`: initializes plugins, policy, config; orchestrates pipeline/autopilot
- **`core/pipeline.rs`** — Sequential layer processing (Passive → Discovery → Scanning → Verification → Exploitation → PostExploitation)
- **`core/orchestrator.rs`** — Multi-agent swarm coordinator (V4.0) for parallel execution with inter-agent communication
- **`core/reactive_engine.rs`** — Autonomous attack chain generation (attack graph → execution → depth limits)
- **`core/plugin_loader.rs`** — Dynamic loading + registration of scanner/discovery plugins
- **`core/sink.rs`** — Abstract output layer (JSONL, PostgreSQL, webhooks, Discord, NATS, timeline)
- **`core/factory.rs`** — Engine construction; infrastructure detection (HW profile → concurrency tuning)
- **`core/approval_gate.rs`** — Dual-gate system for destructive probes (config flag + env var)
- **`core/policy.rs`** — Scope/scope_id matching, HackerOne sync (V15.1)
- **`core/resource_manager.rs`** — System resource tracking (RAM, CPU)

### Plugin Architecture

**ScannerPlugin** trait (async):
```rust
fn name() -> &'static str
fn metadata() -> PluginMetadata  // risk_level, layer, capabilities, cost, destructive flag
async fn check_dependencies() -> Result<bool>
async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>>
```

**DiscoveryPlugin** trait:
```rust
async fn discover(&self, target: &TargetHost) -> Result<Vec<DiscoveryResult>>
```

**Plugin Metadata** fields:
- `target_type` — Host/Web/Network/Mobile/Container/Cloud
- `layer` — Which phase: Passive, Discovery, Scanning, Verification, Exploitation, PostExploitation
- `is_destructive` — Probes requiring approval gate (dual-gate enforcement)
- `capabilities` — Enum (PortScanning, XssScanning, etc.) for selection logic
- `cost` — Token budget impact (swarm mode respects max_tokens)

### Scanning Layers (ScanLayer)

1. **Passive** — OSINT, no network contact
2. **Discovery** — Subdomain enum, ASN mapping, TLS fingerprinting
3. **Scanning** — Port scanning, service detection, version detection
4. **Verification** — Nmap NSE, config audits, IAM assessment
5. **Exploitation** — SQLi, XSS, auth bypass, cloud metadata extraction
6. **PostExploitation** — C2 integration, persistence, privilege escalation

### Target Types

- **Web** — URLs with schemes (http://example.com)
- **Network** — IP:port or IP range
- **Host** — Single hostname/IP
- **Mobile** — APK/IPA file path
- **Container** — image:tag reference
- **Cloud** — Cloud provider resource ID

### Execution Modes

1. **Pipeline Mode** (default) — Sequential layer-by-layer processing
2. **Autopilot Mode** (`--autonomous`) — Reactive engine + approval gates for destructive ops
3. **Swarm Mode** (`--swarm`) — Multi-agent orchestrator with inter-agent messaging
4. **Worker Mode** (`--worker`) — Distributed node pulling jobs from PostgreSQL queue

## Safety & Policy System

### V15.1 Critical Controls

**Destructive Probe Double-Gate:**
- High-impact probes (e.g., N=1000 Alias Amplification) disabled by default
- Require BOTH:
  1. Config flag: `allow_destructive_probes: true` in tactical context
  2. Environment variable: `REDTEAM_DESTRUCTIVE=1`

**Azure Management Token Exfiltration (V14.2):**
- Env var: `REDTEAM_AUTHORIZED_SCOPE=<SCOPE_ID>` must match target scope_id
- Prevents unauthorized tenant takeover

**Reactive Chain Depth Limit:**
- All attack chains capped at **depth 5** via `core.reactive_depth` in Finding
- Prevents exponential blowup in autonomous mode

**Scope Management (V15.1):**
- `--scope-id` flag isolates targets and enables cross-target lateral movement tracking
- HackerOne sync: `SCOPE_SYNC=true` + `H1_API_KEY` auto-fetches authorized scope
- Policy file (JSON) defines in_scope / out_of_scope patterns

### Plugin Approval Gates

Plugins with `is_destructive: true` are blocked unless both gates open. Check metadata in `plugins/mod.rs::Capability` enum.

## Stealth Infrastructure (V14.1)

**DigitalOcean Ephemeral Egress Nodes:**
- `infrastructure/digital_ocean.rs` — Spin up temporary droplets for scanning
- Kill-switch on Ctrl+C: auto-cleanup of all ephemeral droplets
- Requires `DO_TOKEN` env var (DigitalOcean API token)
- Integrates with NATS mesh (`--nats-url`) for decentralized control

## Configuration & Environment

Key env vars read by `utils/config.rs`:
- `REDTEAM_DESTRUCTIVE=1` — Destructive probe opt-in
- `REDTEAM_AUTHORIZED_SCOPE=<ID>` — Azure token scope whitelist
- `SCOPE_SYNC=true` — Auto-fetch H1 scope
- `DO_TOKEN` — DigitalOcean API key
- `C2_URL`, `C2_TOKEN` — Sliver/tactical C2 webhook (HTTPS + SSRF-safe check)
- `OTEL_ENDPOINT` — OpenTelemetry collector (tracing)
- `CERTSTREAM_KEYWORDS` — Cert stream monitoring keywords

Args override env vars. Example:
```bash
./redteam_rust_core --target example.com \
  --vuln-scan \
  --autonomous \
  --swarm \
  --max-tokens 10000 \
  --scope-id acme-2024 \
  --dashboard 8080
```

## Common Development Tasks

### Add a New Scanner Plugin

1. Create `src/plugins/<category>/<tool>/scanner.rs`
2. Implement `ScannerPlugin` trait with metadata
3. Register in `src/plugins/mod.rs::get_all_scanners()` function
4. Add to `PluginRegistry` via factory
5. Test with `cargo test` + integration tests in `src/core/tests.rs`

**Template:**
```rust
use crate::plugins::{ScannerPlugin, PluginMetadata, Capability};
use crate::models::{Finding, RiskLevel, TargetHost};

pub struct MyScanner;

#[async_trait::async_trait]
impl ScannerPlugin for MyScanner {
    fn name(&self) -> &'static str { "my-tool" }
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: "My Tool".to_string(),
            risk_level: RiskLevel::Low,
            is_destructive: false,
            ..Default::default()
        }
    }
    
    async fn scan(&self, target: &TargetHost) -> anyhow::Result<Vec<Finding>> {
        // Implementation
        Ok(Vec::new())
    }
}
```

### Modify Policy / Scope Rules

Edit `core/policy.rs::PolicyProvider` trait or update `policy.json`:
```json
{
  "programs": {
    "acme-2024": {
      "in_scope": ["*.acme.com", "192.168.0.0/16"],
      "out_of_scope": ["admin.acme.com"]
    }
  }
}
```

### Debug a Plugin

Use `tracing` macros (already configured):
```rust
use tracing::{info, debug, warn, error};

debug!("Plugin starting for target: {:?}", target);
```

Run with detailed logging:
```bash
RUST_LOG=debug cargo run --release -- --target example.com
```

JSON logs (structured for parsing):
```bash
./redteam_rust_core --target example.com --json-logs
```

### Run Worker Mode (Distributed)

Setup PostgreSQL queue table:
```sql
CREATE TABLE scan_queue (
  id SERIAL PRIMARY KEY,
  host VARCHAR NOT NULL,
  target_type VARCHAR NOT NULL,
  tactical_context JSONB,
  status VARCHAR DEFAULT 'pending',
  claimed_by VARCHAR,
  priority INT DEFAULT 0,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE workers (
  id VARCHAR PRIMARY KEY,
  status VARCHAR,
  last_seen TIMESTAMP
);
```

Then:
```bash
# Terminal 1: coordinator (enqueues targets)
./redteam_rust_core --target example.com --postgres-url postgres://...

# Terminal 2+: worker nodes
./redteam_rust_core --worker --postgres-url postgres://... --node-id worker-1
```

### Enable Dashboard & Real-Time Mission Injection

```bash
./redteam_rust_core --target example.com --dashboard 8080
# Access: http://localhost:8080/?token=$(cat workspace/logs/dashboard.token)
```

Dashboard allows live mission injection (new targets added mid-scan).

## Key Invariants & Pitfalls

1. **TargetHost.scope_id** — Always set; used for scope isolation and lateral movement tracking
2. **Finding.reactive_depth** — Incremented by reactive engine; checked against depth 5 limit
3. **Plugin cost** — Token budget tracks cost; swarm respects max_tokens across all agents
4. **Approval gates** — Destructive plugins must check both env var AND config flag before firing
5. **SQLx prepare check** — Run before commits; ensures runtime query validity
6. **Proxy manager** — Singleton; shared across all plugins. Call `.rotate_proxy()` for stealth
7. **Resource manager** — Monitors RAM; plugins should respect `config.soft_memory_limit_mb`

## Testing Strategy

- Unit tests live inline in modules (e.g., `#[cfg(test)] mod tests`)
- Integration tests in `src/core/tests.rs` test end-to-end pipeline
- Avoid mocking database; use test PostgreSQL fixtures
- Wiremock for HTTP mocking (external APIs)

## Known Issues & TODOs (Sprint 4.2 Backlog)
- `rquest` (TLS impersonation) temporarily disabled due to yanked versions. Intent tracked via `tls-impersonation` feature.
- `JA4S` (Server Fingerprinting): Prober currently returns a **placeholder** ("t130200_1301_000000000000"). Real prober implementation deferred to Sprint 4.2.
- `SharpHound 2.0`: Supported via `AdIngestor` schema adaptation and `bloodhound.rs` case-insensitive matching.
- Mobile feature requires MobSF API key (see placeholder check in plugins/mod.rs)
- NVD Monitor requires `NVD_API_KEY` for real-time CVE correlation

## References

- **Plugin metadata** — `src/plugins/mod.rs::Capability` enum defines all scan types
- **Findings model** — `src/models/findings.rs::Finding` + reactive_depth field
- **Policy rules** — `src/core/policy.rs::PolicyProvider` trait
- **Engine config** — `src/core/engine/app.rs::EngineConfig` struct
- **Sink interface** — `src/core/sink.rs::DataSink` trait for output backends

## Active Audit Status
- **Status**: Sprint 5 CLOSED (Stage 5.D Admitted via Option D)
- **Next**: Sprint 6 Charter Definition
- **HEAD**: 0c71b34
- **Baseline SHA256**: f65085dc14e274afb071dec17774ed49bc5c58b92cdf739dec87f256445da058
- **Authority**: Stage admission verdict is issued solely by the auditor; coder has no authority to self-attest admission.
- **MCP ownership**: `osint-ultimate` custom development automation server maintained by the Architecture team.


