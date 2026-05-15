# Project Historial - Mimikri RedTeam Core (V15.1)

## Sprint 3: Advanced Cloud & GraphQL Hardening (2026-05-14)

### [COMPLETED]
- **Deduplication Layer**:
    - Refined `SimHash` with 3-character byte shingling for robust near-duplicate detection.
    - Implemented `SimilarityEngine` with `BkTree` (TLSH) and `SimHashBkTree` (SimHash) integration.
    - Implemented **Evidence Merging** strategy instead of simple discard. Near-duplicates now merge their metadata into the original finding and track their origins in `merged_from`.
    - Set Hamming distance threshold to `5` for 64-bit SimHash (~93% similarity).
- **Cloud Metadata Exploitation**:
    - Expanded `ImdsBypassScanner` with deep probes for GCP (project-id, scopes, recursive attributes).
    - Added high-risk Azure probes (Management/KeyVault tokens) with a mandatory `REDTEAM_AUTHORIZED_SCOPE` environment variable gate.
- **GraphQL Security**:
    - Replaced static depth probes with a **Binary Search Convergence** algorithm (lo=1, hi=100) to identify exact depth limits.
    - Added **Alias Amplification DoS** test with configurable alias count (default 50, opt-in 1000 via `allow_destructive_probes`).
    - Implemented jitter (200-800ms) between probes to avoid WAF detection.
- **Reactive Engine Integration**:
    - Explicitly registered the `FINDING_SSRF` -> `ImdsBypassScanner` chain.
    - Implemented a **Chain Depth Safety Gate** (max depth = 5) to prevent infinite reactive loops.
- **Infrastructure**:
    - Audited `sqlx` 0.8 migration. Verified that no `query!` macros are currently used, reducing compile-time type inference risks.

### [VERIFICATION]
- `SimilarityEngine` near-duplicate merging test: **PASSED** (2 findings with 3-char diff merged successfully).
- `BkTree` SimHash index test: **PASSED**.
- `ReactiveEngine` chain depth propagation: **VERIFIED**.

### [OPEN / NEXT]
- Sprint 4: JA4 TLS Fingerprinting (JA4, JA4S, JA4H) via `tls-parser`.
- Integration of `rquest` for impersonation (waiting for non-yanked versions).
- Binary Search convergence for very large depth limits (>100).
