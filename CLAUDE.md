# CLAUDE.md — OsintUltimate | V13 STEALTH

## Security Conventions (CRÍTICO — LEER ANTES DE ESCRIBIR)
- **SSRF**: Todas las operaciones de red deben pasar por `utils::liveness::is_ssrf_safe_host`. MANDATORIO.
- **IP Pinning**: Usar `target.pinned_addr()` para prevenir DNS Rebinding en herramientas ofensivas.
- **PoC Safety**: Usar enums `ValidatedPoc`; prohibida la inyección de comandos CLI mediante strings no verificados.
- **Integridad**: Plugins dinámicos requieren verificación Ed25519 vía `OSINT_PLUGIN_PUBKEY`.

## Project Context (Compressed)
- OSINT/Redteam Rust. Tokio (Async). Reqwest, Hickory-resolver, Libloading. Linux/Windows.
- Build: `cargo build --release` | Test: `cargo test --all-targets` | Audit: `cargo audit`.

## Architecture Map
- `core/engine`: State/Lifecycle.
- `core/pipeline`: Data flow (Discovery -> Liveness -> Scanning).
- `core/swarm`: Multi-agent autonomous logic. TokenBudget enforced.
- `core/poc_validator`: Template-based execution. NO raw injection.
- `core/plugin_loader`: Ed25519-signed dynamic loading.
- `infrastructure/proxy`: Stealth egress. VPS/Static exit nodes.

## Rust & Development
- Errors: `anyhow::Result` + `.context()`.
- Concurrency: `tokio::sync::mpsc` preferred over Mutex.
- Execution: Use `stealth_command` wrapper for binaries.

## Agent Routing logic
- CLAUDE: Architecture, Hardening, Traits, Swarm Concurrency, PoC safety.
- GEMINI FLASH: Boilerplate, Tests, Glue code, Tactical context compression.
- KIMI: Full audit, V12->V13 Regressions, Log correlation.

## Active Audit Status (V13)
- Status: Fixing Managed Exit Leakage (IP leak during droplet provisioning).
- Pending: Initial Egress readiness gate integration.

## Files Locked (Review Required)
- `core/poc_validator.rs`, `core/plugin_loader.rs`, `utils/liveness.rs`.

## Anti-Patterns (NUNCA HACER ESTO)
- **Unwrap/Expect**: Prohibido en rutas de `core/` e `infrastructure/`.
- **Raw Commands**: Nunca usar `std::process::Command` directamente (usar `stealth_command`).
- **Proxy Bypass**: En modo `--stealth`, los plugins no deben usar clientes `reqwest` directos.
