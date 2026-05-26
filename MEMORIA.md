# MEMORIA

## Sprint 12 — Config-Driven Intelligence + Zero-Cost Audit
- **Stage 12.A** (`db0ed3d`): Zero-cost default path integration test — proves free-tier-only config emits `CredentialLeak` findings via HIBP Pwned Passwords.
- **Stage 12.B** (IN PROGRESS): Config-driven refactor of 4 intelligence scanners (`AlienVaultOtxScanner`, `AbuseIPDBScanner`, `GreyNoiseScanner`, `CredentialLeakScanner`) to use `Config::from_env()` instead of direct `std::env::var()`.
  - Added 3 missing `Config` fields: `alienvault_otx_max_ips_per_scan: usize`, `greynoise_api_key: Option<String>`, `hibp_api_key: Option<String>`.
  - Zero behavioral change; all default values preserved.
  - Test discipline: 171 lib + 8 bin + 3 OOB + 1 zero-cost = all green.

## Sprint 11 — Intelligence Scanners
- **Stage 11.A**: `Wafw00fScanner` subprocess plugin with JSON parsing, `Category::WafDetected`.
- **Stage 11.B**: `FaviconHashScanner` with MMH3 hash, Shodan/FOFA pivot.
- **Stage 11.C**: `CredentialLeakScanner` with h8mail subprocess, HIBP Pwned Passwords k-anonymity, HIBP Breached Account gating.
- **Stage 11.D/E**: Noseyparker defer doc + backlog niche tools doc.

## Sprint 7.5 — Inter-sprint stabilization (COMPLETE)
- Stage 1.5.A: Async DB budget sync (d6f3506).
- Violation count: 18 cumulative.
