# OsintUltimate - Red Team Rust Core (SSOT)

## Core Infrastructure
- **Proxy Manager (基/基理)**: 
  - Managed exits (Azure/Oracle split) for true fail-closed egress.
  - Identity bonding (User-Agent persistence per host) and latency-based prioritization.
- **Stealth Executor (行/安行)**: 
  - High-OPSEC execution mode (Ghost) with environment sanitization.
  - Integration with Sandbox Dispatcher for untrusted plugin execution.
- **Tiered AI Router (路/析)**:
  - Dynamic routing between `Lite` (speed/cost) and `Premium` (reasoning) LLMs.
  - Context-aware prompt optimization (Caveman/Wenyan).
- **Validation Pipeline (查/穴查)**:
  - V15 Anti-Hallucination: Negative Control + Proof-of-Execution + OOB (Out-of-Band) verification.

## Build & Test Commands
- Main Build: `cargo build -p redteam_rust_core`
- Active Test: `cargo test -p redteam_rust_core`
- Strict Audit: `cargo clippy -p redteam_rust_core -- -D warnings`
- Tool Context: Refer to @[rust_context.txt] for repository mapping.

## Project Rules (法)
- **English Only**: Documentation and comments strictly EN.
- **Zero Warnings (查)**: No technical debt. 
- **No Dead Code**: Direct deletion of unused artifacts.
- **FFI Safety**: `#[repr(C)]` for all cross-boundary structures.

## Active Audit Status (查境)
- PHASE: 1.5 ZERO-DEBT BASELINE
- GOAL: Resolve 15 remaining lints (including critical Scrubber Regex bug).
- CONTEXT: Repository snapshot loaded from `rust_context.txt`.
