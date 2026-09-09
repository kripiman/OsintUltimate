# ADR-012: AI Context Pipeline Hardening & Dense Serialization

## Status
Accepted

## Context
As the autonomous red team engine scales (multi-agent swarms running against large target surfaces), LLM token consumption in context-rich loops becomes a significant latency and economic bottleneck. We have identified two major inefficiencies in the current pipeline:
1. **Low-Entropy Data Structures**: Emitting full JSON-serialized findings containing redundant strings (e.g., full severity names, status indicators, and large body footprints) inflates contexts without adding signal.
2. **Header Optimization Regression**: In Sprint 4.1, minification logic stripped `server` and `x-powered-by` headers—critically removing fingerprint data needed by downstream LLM planners and scanners for custom-tailored exploitation chains.
3. **Compilation Gates & Typestate Breaks**: Conditionally gating `StealthClientBuilder` led to deep type-inference failures in core modules during feature switches. A permanent compilation strategy is required.

## Decisions

### 1. Unified Tactical Header Whitelist
We will enforce a robust header-strip model in `ContextCompressor`. The following headers **MUST** be explicitly whitelisted and preserved:
*   `server`
*   `x-powered-by`
*   `location`
*   `www-authenticate`
*   `x-content-type-options`

All session noise, transport layers, and credential noise (`cookie`, `auth`, `user-agent`) will be stripped to guarantee compliance with security boundaries while preserving crucial tactical fingerprints.

### 2. Dense Finding Serialization Format
We standardize on a compact, highly optimized serialization scheme for `RouteLevel::Local` and `RouteLevel::Mid` routing tiers:
*   **Keys**: Shortened to single-character representation (`s` for severity, `d` for description, `cvss` for CVSS score, `cf` for verification/confidence status, `cat` for category, and `ev` for sanitized evidence).
*   **Values**: Severities mapped to high-density chars (`C`ritical, `H`igh, `M`edium, `L`ow, `I`nfo). Verification/confidence status mapped to `V` (Verified) or `P` (Potential). Description snippets aggressively truncated to 150 characters max.

### 3. Target Lean Compression Integration
Tier 0 LLM models (e.g., local Ollama or basic OpenAI invocations) do not require full O(N) technological stack traversal. We mandate the use of `compress_target_lean` across all local clients to eliminate runtime processing overhead and reduce context footprints on simpler routing paths.

### 4. StealthClientBuilder Permanent Non-Gated Compilation
To maintain absolute workspace compilation parity (0 warnings, 0 clippy warnings) under any standard feature configuration, `StealthClientBuilder` will remain unconditionally compiled. 
*   Spoofing pipelines requiring heavy external dependencies (such as TLS impersonation engines) will be dynamic-dispatched or abstract-wrapped internally to prevent compilation blocks without leaking experimental feature flags to clean-built modules.

## Consequences
*   **Token Savings**: Over 15–20% direct reduction in prompt context lengths across typical HTTP scanning and planning targets.
*   **Better Signal-to-Noise**: Preservation of `server` and `x-powered-by` guarantees that target fingerprinting remains highly visible to LLM agents.
*   **Zero Compilation Fragility**: Permanent de-gating of `StealthClientBuilder` resolves typestate issues and keeps standard development flows warning-free.
