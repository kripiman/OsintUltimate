# CLAUDE.md — OsintUltimate

## Project
Offensive security and OSINT framework in Rust designed for high-performance red team operations.

## Stack
- **Runtime**: Tokio (Async-first).
- **Crates**: Reqwest (HTTP), Serde (JSON), Ed25519-dalek (Crypto), Hickory-resolver, Libloading.
- **Edition**: Rust 2021.
- **Targets**: Linux (Main), Windows (Dynamic Plugin support).

## Build & Test
- **Build**: `cargo build --release`
- **Test**: `cargo test --all-targets`
- **Audit**: `cargo audit` (Security dependency check)

## Architecture
- `core/engine`: Orchestrates application state and lifecycle.
- `core/pipeline`: Manages data flow: Discovery -> Liveness (IP Pinning) -> Scanning.
- `core/swarm`: Multi-agent autonomous logic with TokenBudget constraints.
- `core/poc_validator`: Template-based execution of PoCs from AI findings.
- `core/plugin_loader`: Secure dynamic loading of Ed25519-signed shared libraries.
- `infrastructure/proxy`: Stealth egress management via static and VPS exit nodes.
- `models`: Core data structures (`TargetHost`, `Finding`) with serialization support.

## Security Conventions (CRÍTICO — leer antes de escribir código)
- **SSRF**: All network-bound ops must pass through `utils::liveness::is_ssrf_safe_host`.
- **IP Pinning**: Use `target.pinned_addr()` to prevent DNS Rebinding in offensive tools.
- **PoC Safety**: Use `ValidatedPoc` enums; no raw CLI command injection via unverified strings.
- **Integrity**: Dynamic plugins require Ed25519 verification via `OSINT_PLUGIN_PUBKEY`.

## Rust Conventions
- **Error Handling**: Use `anyhow::Result` with descriptive `.context()` for tracing.
- **Async**: Prefer `tokio::sync::mpsc` channels over shared Mutex state.
- **Isolation**: Use `stealth_command` wrapper for external binary execution.

## Anti-Patterns (NUNCA hagas esto)
- **Unwrap/Expect**: Prohibited in `core/` and `infrastructure/` paths.
- **Raw Commands**: Never use `std::process::Command` directly (use `stealth_command`).
- **Proxy Bypass**: In `--stealth` mode, plugins must not use raw `reqwest` clients.

## Agent Routing
- **Claude**: Architectural refactoring, security hardening, complex trait logic,
  concurrency in `core/swarm`, `poc_validator` changes.
- **Gemini Flash**: Boilerplate generation, tests unitarios, glue code entre módulos,
  compresión de contexto táctica.
- **Kimi**: Auditorías de codebase completo, análisis de regresiones entre versiones
  de auditoría (V12→V13), correlación de hallazgos en logs extensos.

## Active Audit Status (V13 Stealth Hardening)
- **FIXED (V12)**: PoC Injection (CRIT-001), Swarm Race-Conditions, Windows TOCTOU.
- **ACTIVO (V13)**: Managed Exit Leakage (AI analysis bypassing proxies).
- **NUEVO**: Initial Egress readiness gate (IP leak during droplet provisioning).

## Files to Never Touch Without Review
- `redteam_rust_core/src/core/poc_validator.rs` (Exploit safety logic)
- `redteam_rust_core/src/core/plugin_loader.rs` (Integrity enforcement)
- `redteam_rust_core/src/utils/liveness.rs` (SSRF/DNS security checks)
