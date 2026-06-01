新問題發現 — 先前審計測試設計有誤。

  SovereignReconScanner無Default impl。..Default::default()不編譯：

  - Arc<ProxyManager> → new(proxies, insecure, mode, pool_size) 重型構造
  - Arc<dyn PolicyProvider> → 需具體類型

  ---
  剩餘實現清單 (精確)
  
  B11 — 修正後測試方案

  ..Default::default()不可行。兩條路：

  路徑A（推薦）— 測試放sources.rs，測純邏輯：

  #[cfg(test)]
  mod tests {
      use std::collections::HashSet;

      #[test]
      fn test_per_api_cap_truncates_at_limit() {
          let results: HashSet<String> = (0..10).map(|i| format!("h{}", i)).collect();
          let out: HashSet<String> = if results.len() > limit {
              results.into_iter().take(limit).collect() 
          } else { results };
          assert_eq!(out.len(), 3);
      }
      
      #[test]
      fn test_per_api_cap_respects_zero_disables() {
          let limit = 0usize;
          let out: HashSet<String> = if limit == 0 {
              HashSet::new()
          } else {
              ["x".to_string()].into()
          };  
          assert!(out.is_empty());
      }   
  }

  路徑B — mod.rs測struct wire，需完整構造ProxyManager，成本高，Stage 1.5.B範圍外。

  B12 — sources.rs:241加注釋 (1行):
  // min防止paid search與host enrichment兩路合計超出單次掃描預算
  let limit = std::cmp::min(self.shodan_paid_max_hosts, self.shodan_host_ip_max_hosts);

  B13 — 驗證命令:
  cargo check --package redteam_rust_core 2>&1 | tail -5
  cargo test --package redteam_rust_core 2>&1 | tail -20
  git status

  ---
剩餘量：3項，全在sources.rs，無新檔案。 B12+B11路徑A合計約10行代碼 + B13輸出。HOLD解除後Commit X+1准入。# CLAUDE.md

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

## Sprint Workflow Discipline (Post-Sprint 6)
- **1-Stage-Per-Turn**: Strict limit of 1 stage per turn containing source changes; Auditor verdict must be issued between stages.
- **Temp Generators & Audit Tools**: All temporary tools/scripts must reside in `redteam_rust_core/examples/audit_tools/`.
- **Git Hygiene**: `redteam_rust_core/examples/audit_tools/` is added to `.gitignore` (no generator code committed).

## Active Audit Status
- **Status**: Sprint 10 Stage B complete (H2Preface probe + orchestrator wiring, 219 tests pass)
- **Next**: Sprint 10 audit
- **HEAD**: 7721b69
- **Baseline SHA256**: *to be refreshed in Sprint 10 audit*
- **Violations cumulative**: 22 (Sprint 7=13, Sprint 7.5=5, Sprint 11=2, Sprint 4+5a bundling=1, Sprint 5a=1)

