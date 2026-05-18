# ARCH-12 Phase 2 Plan: AI Context Pipeline Hardening

This plan defines the official scope and execution stages for **ARCH-12: AI Context Pipeline Hardening (Phase 2)**. 

## Proposed Architecture & Changes

We decompose the work into three distinct stages to address the outstanding optimizations in `AIP.md` and satisfy compilation and token safety requirements.

---

### Stage 1: Fix Header Strip Regression (P0)

*   **Problem**: `compressor.rs` strips or fails to consistently retain the tactical fingerprinting headers (`server` and `x-powered-by`).
*   **Scope**:
    *   **Main Context Path**: In `minify_evidence_object` (line 125), verify that `server` and `x-powered-by` are present in the whitelist and retained.
    *   **Swarm Context Path**: In `compress_swarm_context` (line 80-81), `minify_headers` was previously hardcoded to only retain `server` (e.g. `Self::minify_headers(ev, &["server"])`). Fix this to retain **both** tactical headers: `&["server", "x-powered-by"]`.
*   **Verification**: Ensure all HTTP header tests verify retention of both headers in both paths.

### Stage 2: Dense Encoding & compress_target_lean

*   **Dense Finding Encoding (AIP 2.3)**:
    *   Implement and standardize `compress_finding_dense` (or refine `compress_finding` to be extremely dense) using compact keys and severities (`C`, `H`, `M`, `L`, `I`) to yield ~15-20% context reduction.
*   **Target Lean Integration (AIP 2.2)**:
    *   Ensure `compress_target_lean` is consistently leveraged across Tier 0 local workflows (e.g., `OllamaClient` and `OpenAIClient`) to avoid O(N) technological stack traversal overhead.

### Stage 3: StealthClientBuilder Decision

*   **ADR-012 Integration**:
    *   Commit and ratify `ADR-012-AI-CONTEXT-HARDENING.md` within the `DOCS` folder to establish the permanent non-gated status of `StealthClientBuilder` to avoid typestate blocks during features-off builds.

---

## Verification Plan

### Exit Gates

| Gate | Check | Mode |
|---|---|---|
| **G1** | `cargo build --release` compiles with 0 warnings | Local |
| **G2** | `cargo test --package redteam_rust_core` passes all unit & integration tests | Local |
| **G3** | `cargo clippy` is warning-free (`-- -D warnings`) | Local |
| **G4** | **Verify Parity**: Zero drift against `golden_baseline.json` | Automated |

### Automated Tests
- `test_header_strip_retention`: Asserts that `server` and `x-powered-by` are retained on both compression paths.
- `test_dense_finding_encoding`: Asserts compact keys and values.
