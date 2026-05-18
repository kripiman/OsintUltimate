# ARCH-12 Tasks: AI Context Pipeline Hardening

- `[x]` **Stage 1: Fix Header Strip Regression (P0)**
    - `[x]` Modify `compress_swarm_context` in `compressor.rs` to retain both `server` and `x-powered-by` in its whitelist parameter.
    - `[x]` Verify that `minify_evidence_object` whitelists and retains both `server` and `x-powered-by` headers on the main pipeline path.
    - `[x]` Add a comprehensive unit test `test_header_strip_retention` in `compressor.rs` validating both paths.
- `[x]` **Stage 2: Dense Encoding & Target Lean Integration**
    - `[x]` Build and test `compress_finding_dense` in `compressor.rs`.
    - `[x]` Integrate dense encoding across `router.rs` classification and analysis stages to reduce token bloat.
    - `[x]` Ensure local LLM clients (e.g. `OllamaClient`, `OpenAIClient`) utilize `compress_target_lean` instead of general `compress_target` where appropriate.
- `[ ]` **Stage 3: StealthClientBuilder Decision (ADR-012)**
    - `[ ]` Formally ratify `ADR-012-AI-CONTEXT-HARDENING.md` by committing and pushing it to git.
- `[ ]` **Verification & Validation**
    - `[ ]` Verify G1 (Build Parity: 0 warnings)
    - `[ ]` Verify G2 (Tests PASS)
    - `[ ]` Verify G3 (Clippy Clean)
    - `[ ]` Verify G4 (Verify Parity / Zero Drift)
