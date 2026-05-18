# ADR-011: Orchestrator Domain Decomposition & SSOT Strategy

## Status
Proposed / Active

## Context
The project is refactoring the monolithic `Orchestrator` and `SwarmOrchestrator` into domain-specific modules. This has led to duplicate paths for C2 and Swarm logic (e.g., `core/c2/` vs `core/orchestrator/c2/`).

## Decision
1. **C2 Domain SSOT**: `redteam_rust_core/src/core/orchestrator/c2/` is designated as the primary domain for C2 feedback logic. 
   - **Stage 2 Scope**: Full migration of `C2Operator` trait, typestates, `sliver_proto`, and `sliver_feedback` logic from `src/core/c2/` to `src/core/orchestrator/c2/`.
   - `core/c2/` directory will be deleted at the end of Stage 2.

2. **Swarm Domain SSOT**: `redteam_rust_core/src/core/orchestrator/swarm/` is designated as the primary domain for all Swarm-related logic.
   - `budget.rs` and `inventory.rs` will be moved here using `git mv` to preserve history.
   - `SwarmOrchestrator` logic will be decomposed into `swarm/agent.rs` and `swarm/correlation.rs`.

3. **Infrastructure Config Compatibility**:
   - `InfrastructureConfig` will maintain backward compatibility with legacy CLI flags (`--sliver-*`) using `#[serde(alias = "...")]`.
   - A dedicated JSON-only parity test will ensure that old configurations still deserialize correctly without requiring external YAML engines.

4. **Lint & Build Integrity**:
   - The project enforces a "Zero Warnings" (G1) and "Clippy Clean" (G3) policy for all NEW code and modified areas.
   - Existing lint debt will be addressed incrementally during domain transitions.

## Consequences
- Requires workspace-wide import updates.
- Temporary duplication of some traits during migration.
- Improved SRP (Single Responsibility Principle) and maintainability.

## RFC: Formal De-gating of StealthClientBuilder
To prevent type-inference breakage and compilation cascades across multiple modules (such as out-of-band validation and negative control loops) under default builds, the `StealthClientBuilder` is formally de-gated from the `tls-impersonation` feature. It is compiled unconditionally. Active spoofing configurations inside `stealth_http.rs` remain gated to avoid dependency blocks.

