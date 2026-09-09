# ADR-013: LLM Provider Rate Limiting & Retry-After Backoff

## Status
Accepted

## Context

The TieredAIRouter orchestrates multiple LLM providers across four tiers (Local, FreeTier, Mid, Premium). As the engine scales to multi-target swarms, two operational risks emerge:

1. **Credit Bleed from 429s**: Without local rate-limiting guards, the router may burn through API quotas by repeatedly hammering a provider that has already returned HTTP 429. This is especially dangerous for FreeTier providers (Google AI Studio) with strict daily quotas.
2. **Deadlock from Naive Sleep**: Some providers return `Retry-After: 86400` (24 hours) on daily-quota exhaustion. Sleeping the full duration blocks the entire routing chain, stalling the scan.
3. **No Structured Retry Metadata**: `RouterError::RateLimited` was a simple enum variant with no `retry_after` or `daily_quota` fields, preventing intelligent backoff decisions.

## Decisions

### 1. Per-Provider Local Rate Limiting with `governor`

We introduce `ProviderRateLimiter` (`src/core/ai/rate_limiter.rs`) backed by the `governor` crate (v0.6). Each provider kind registers its own in-memory token bucket:

- **Groq**: 30 RPM default
- **Google AI Studio**: 15 RPM default
- **OpenRouter**: 20 RPM default

Configurable via environment variables (`GROQ_RPM`, `GOOGLE_AI_STUDIO_RPM`, `OPENROUTER_RPM`).

Before every provider call, the router checks `rate_limiter.check(&entry.kind)`. If the bucket is empty, the router skips that provider for this iteration (no sleep), allowing failover to the next provider in the tier or upward tier.

### 2. Structured `RouterError::RateLimited`

`RouterError::RateLimited` is upgraded to a struct variant:

```rust
RateLimited {
    retry_after: Option<Duration>,
    daily_quota: bool,
}
```

- `retry_after`: Parsed from error messages containing "retry-after: N" or extracted from HTTP headers by individual clients.
- `daily_quota`: Detected when the error message contains "daily quota", "quota exceeded", or "quota limit".

### 3. Capped Sleep Before Failover

When a provider returns `RateLimited { retry_after: Some(d), .. }`, the router sleeps **only up to 30 seconds** before trying the next provider:

```rust
let capped = d.min(Duration::from_secs(30));
tokio::time::sleep(capped).await;
```

This prevents deadlock from 24-hour `Retry-After` values while still respecting short provider cool-downs (1–30s).

### 4. Daily Quota Bypass

If `daily_quota: true`, the router logs a critical warning and skips the provider. The provider remains available in the `ArcSwap` map for future scans, but the current scan does not waste retries on it.

### 5. FreeTier Gating

`REDTEAM_FREETIER_DISABLED=1` prevents registration of FreeTier providers in `factory.rs`. This gives operators an emergency kill-switch for quota-sensitive providers without code changes.

## Consequences

- **Credit Protection**: Local governor buckets prevent 429 storms before they start.
- **Predictable Latency**: 30-second cap guarantees no scan stalls beyond a bounded window.
- **Operational Visibility**: Structured `RouterError` enables downstream alerting on daily-quota exhaustion.
- **Zero Breaking Changes**: Existing clients (OpenAI, Gemini, Anthropic, etc.) continue to work unchanged; only new clients and the router error path are affected.
