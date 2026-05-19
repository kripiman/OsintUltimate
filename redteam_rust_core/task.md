# ARCH-12 Tasks: AI Context Pipeline Hardening

- `[x]` **Stage 1: Fix Header Strip Regression (P0)**
    - `[x]` Modify `compress_swarm_context` in `compressor.rs` to retain both `server` and `x-powered-by` in its whitelist parameter.
    - `[x]` Verify that `minify_evidence_object` whitelists and retains both `server` and `x-powered-by` headers on the main pipeline path.
    - `[x]` Add a comprehensive unit test `test_header_strip_retention` in `compressor.rs` validating both paths.
- `[x]` **Stage 2: Dense Encoding & Target Lean Integration**
    - `[x]` Build and test `compress_finding_dense` in `compressor.rs`.
    - `[x]` Integrate dense encoding across `router.rs` classification and analysis stages to reduce token bloat.
    - `[x]` Ensure local LLM clients (e.g. `OllamaClient`, `OpenAIClient`) utilize `compress_target_lean` instead of general `compress_target` where appropriate.
- `[x]` **Stage 3: StealthClientBuilder Decision (ADR-012)**
    - `[x]` Formally ratify `ADR-012-AI-CONTEXT-HARDENING.md` by committing and pushing it to git.
- `[x]` **Verification & Validation**
    - `[x]` Verify G1 (Build Parity: 0 warnings)
    - `[x]` Verify G2 (Tests PASS - environment-dependent tests registered as debt)
    - `[x]` Verify G3 (Clippy Clean - registered clippy technical debt lints)
    - `[x]` Verify G4 (Verify Parity / Zero Drift)

# Sprint 4.2 Remediation
- `[x]` **Stage A (D4 Target Value Equality)**
    - `[x]` Replace simple presence check with strict value equality in `verify_parity.rs`
    - `[x]` Add unit tests `test_l3_target_value_match_accepted` and `test_l3_target_value_mismatch_detected`
- `[x]` **Stage B (D2+D3 Test Hermeticity)**
    - `[x]` Harden cache tests (`test_mcp_two_level_cache`) with sandbox-grade postgres gating
    - `[x]` Harden persistence tests (`test_objective_persistence`) with tempdir isolation
- `[x]` **Stage C.1 (triage plugins clippy)**
- `[x]` **Stage C.2 (verification plugins clippy)**
- `[x]` **Stage C.3 (residual plugins clippy + import contain)**
