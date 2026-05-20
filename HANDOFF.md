# Sprint 7.5 Handoff — Inter-sprint stabilization (2026-05-20)

## Closed Status
- **Stage 1.5.A (Fix A)**: Fully implemented async database-synchronized budget checks (`d6f3506`).
  - Added async `can_spend_db` in `api_budget.rs` using atomic updates on `mcp_stats` table.
  - Added `can_spend_mem` memory fallback for offline tests.
  - Updated passive recon handlers in `sources.rs` to `.await` budget queries.
  - Decoupled `shodan_keyring.rs` from missing Config fields via environment fallback.
  - Added concurrent, panic-safety, and db-sync unit tests to `api_budget.rs`.

## Verification
- **Compilation**: Clean build with no warnings.
- **Unit Tests**: Targeted `cargo test utils::api_budget` executed successfully (3/3 tests passed).

## Next Steps
- **Stage 1.5.B: Fix B (Per-API Caps in Config)**: Introduce bounding/truncating limits and zero-disables in configuration, applying to target counts in `mod.rs`.
- **Stage 1.5.D: Fix D (Canonical Params in Cache)**: Refactor `ApiCache` key generation using RFC 3986 parameter sorting.
- **Stage 1.5.S: Smoke Test & Benchmarks**: Run local benchmarks and integration scans on hackerone.com.