# Implementation Plan v2 - Supply Chain Security (Sprint 1B)

This plan outlines the integration of **Syft**, **Grype**, and **Cosign** into the OsintUltimate compliance layer. This version addresses target detection bugs, orchestrator chaining, and policy whitelisting.

## 🛡️ Critical Fixes & Hardening

### 1. Target Detection (main.rs)
- **Problem**: `alpine:latest` is currently detected as `TargetType::Network` due to the colon, bypassing container plugins.
- **Fix**: Update the heuristic in `main.rs` or add an explicit `--image` flag.
- **Logic**: If a target has one colon and no dots (or is explicitly passed via `--image`), it's a `TargetType::Container`.

### 2. Policy Whitelisting (policy/mod.rs)
- **Binary Whitelist**: Add `syft`, `grype`, and `cosign` to the `StaticPolicy` whitelist.

### 3. Orchestrator Chaining (orchestrator.rs)
- **New Chain Rules**:
    - `FINDING_SBOM_INVENTORY` (Syft) → Trigger `PLUGIN_GRYPE` and `PLUGIN_COSIGN`.
    - `FINDING_UNSIGNED_IMAGE` (Cosign) → Escalate severity if combined with high-CVSS findings.

### 4. SBOM Sandbox & Data Handling
- **Persistence**: Syft will write the full SBOM JSON to `/tmp/osint_scans/{uuid}/sbom.json`.
- **Grype Efficiency**: Grype will consume the existing SBOM file instead of re-scanning the image.
- **Finding Summary**: `FINDING_SBOM_INVENTORY` will contain a dense summary (pkg count, top-level deps) in the evidence, not the full blob.

## 🛠️ Proposed Changes

### [NEW] Plugins
- `src/plugins/compliance/syft.rs`
- `src/plugins/compliance/grype.rs`
- `src/plugins/compliance/cosign.rs`

### [MODIFY] Core Infrastructure
- **constants.rs**: Add `SUPPLY_TIMEOUT_*_SECS` and finding/plugin IDs.
- **config.rs**: Add `cosign_public_key`, `cosign_oidc_issuer`, and timeout fields.
- **mod.rs (plugins)**: Register new plugins.
- **orchestrator.rs**: Update `CHAIN_TABLE`.

## ⚙️ Configuration (.env.oracle)
```env
COSIGN_PUBLIC_KEY_PATH=
COSIGN_OIDC_ISSUER=https://accounts.google.com
SUPPLY_TIMEOUT_SYFT_SECS=300
SUPPLY_TIMEOUT_GRYPE_SECS=600
SUPPLY_TIMEOUT_COSIGN_SECS=120
```

## ✅ Verification Plan
1. `cargo check` (Integrity).
2. `cargo run -- --image alpine:latest` (Target Detection).
3. Verify `scan_result.jsonl` contains the SBOM summary and CVEs from Grype.
