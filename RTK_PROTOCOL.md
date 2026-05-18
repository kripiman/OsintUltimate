# RTK Protocol & Division of Authority

## Division of Authority & Verdict Rules
Stage admission verdict is issued solely by the auditor; coder has no authority to self-attest admission. All attestation flags, logs, and parity reports must be submitted raw and without exit code masking to allow for direct, immutable verification by the auditing pipeline.

## Verification Standards
1. **Raw Command Execution**: Tests and builds must be run directly through standard toolchains (e.g., `cargo`) rather than wrapped scripts that mask exit statuses.
2. **Strict Baseline Comparison**: Findings comparison must enforce exact Option structural matching to protect target identity integrity.
3. **Telemetry & Tele-Audit**: Active audit status must be registered transparently in `CLAUDE.md` and exposed via official MCP server telemetry hooks.
