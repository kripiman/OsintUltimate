# ARCH-11 Phase 1: Orchestrator Domain Decomposition (Revised)

This phase decomposes the monolithic orchestration logic into granular domains (Lifecycle, Swarm, C2) and enforces "Sovereign-grade" integrity through parity gates and deterministic testing.

## User Review Required

> [!IMPORTANT]
> **Parity Gate (G4)**: All architectural changes must maintain functional parity with the Phase 0 baseline (`golden_baseline.json`).
> **Atomic Commits**: Work will be executed in 4 distinct stages to ensure build and test integrity at every step.

## Proposed Architecture

### [Component] core/orchestrator/

#### [NEW] [lifecycle/](file:///home/kripi/Documentos/GitHub/OsintUltimate/redteam_rust_core/src/core/orchestrator/lifecycle/)
- `shutdown.rs`: Shutdown coordination, droplet cleanup, and state-save hooks.
- `monitor.rs`: (Moved from `orchestrator/monitor.rs`) Lifecycle watcher.

#### [NEW] [swarm/](file:///home/kripi/Documentos/GitHub/OsintUltimate/redteam_rust_core/src/core/orchestrator/swarm/)
- `mod.rs`: Swarm orchestration entry point.
- `agent.rs`: Scout/Exploiter/C2Operator/Reporter logic.
- `correlation.rs`: `CorrelationEngine` ingestion and context summary.
- `budget.rs`: (Moved from `core/swarm/budget.rs`).
- `inventory.rs`: (Moved from `core/swarm/inventory.rs`).

#### [NEW] [c2/](file:///home/kripi/Documentos/GitHub/OsintUltimate/redteam_rust_core/src/core/orchestrator/c2/)
- `mod.rs`: C2 feedback domain.
- `sliver.rs`: `SliverAutomator` integration.
- `feedback.rs`: `SliverFeedbackLoop` (gRPC).

#### [MOVE] Intelligence/Enrichment
- `NvdMonitor`: Move to `intelligence/` or `enrichment/` (Decoupled from Swarm).

---

## Execution Stages (Atomic Commits)

### Stage 1: Skeleton & Infrastructure (C1)
- Create empty domain modules in `core/orchestrator/`.
- Register new modules in `orchestrator/mod.rs`.

### Stage 2: Move & Redirect (C2)
- Move `budget.rs`, `inventory.rs` to `orchestrator/swarm/`.
- Move `SliverFeedbackLoop` to `orchestrator/c2/`.
- Update all imports across the workspace.
- **Verification**: `cargo build --release` (0 warnings).

### Stage 3: Domain Extraction (C3)
- Extract logic from `swarm/orchestrator.rs` (monolith) into `swarm/agent.rs` and `swarm/correlation.rs`.
- Implement `InfrastructureConfig` with `serde alias` for backward compatibility with CLI `--sliver-*` flags.
- **Verification**: `cargo test` PASS.

### Stage 4: Cleanup & Finalization (C4)
- Delete legacy `core/swarm/` directory.
- Finalize `lifecycle/` logic (shutdown/cleanup).
- **Verification**: Parity Gate PASS.

---

## Verification Plan

### Exit Gates (Exit Gates)

| Gate | Check | Source |
|------|-------|--------|
| **G1** | `cargo build --release` (0 warnings) | Local |
| **G2** | `cargo test --package redteam_rust_core` PASS | Local |
| **G3** | `cargo clippy -- -D warnings` PASS | Local |
| **G4** | **Verify Parity** (L1<2%, L2 hash, L3 typeid) | `parity.yml` |
| **G5** | **Swarm Determinism**: Dual-run diff = 0 byte | Manual |
| **G6** | **CLI Smoke Test**: `--swarm` vs DVWA target | Manual |

### Deterministic Testing (G5)
1. Run `cargo run --bin capture_baseline -- --mode swarm --target dvwa`.
2. Run again and compare output NDJSON.
3. Diff must be 0 bytes (excluding timestamps if applicable, or normalized).
