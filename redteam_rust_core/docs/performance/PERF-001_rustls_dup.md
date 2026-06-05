# PERF-001 — rustls 0.21 + 0.23 Duplication Risk Register

## Status
Deferred. Documented. No production impact.

## Dependency Structure

```toml
rustls = "0.21"                              # legacy, via reqwest 0.11
webpki-roots = "0.25"
rustls-ech = { package = "rustls", version = "0.23" }  # ECH + TLS 1.3 0-RTT
webpki-roots-ech = { package = "webpki-roots", version = "1.0" }
tokio-rustls = { version = "0.26", features = ["early-data"] }
```

## Why Two Versions Exist

| Feature | rustls 0.21 | rustls 0.23 (aliased rustls-ech) |
|---|---|---|
| Used by | `reqwest 0.11`, legacy TLS client code | `tokio-rustls 0.26`, ECH client, TLS 1.3 0-RTT |
| API | `ClientConfig::builder()` returns `ConfigBuilder< WantsVerifier >` | `ClientConfig::builder_with_provider()` — provider-based crypto |
| Crypto | Ring only | Ring + AWS-LC (configurable via `CryptoProvider`) |
| ECH | Not supported | Supported (ClientHello encryption) |

## Impact Assessment

| Metric | Value | Severity |
|---|---|---|
| Binary bloat (release) | ~500 KB | Low |
| Compile time increase | ~5-10 s | Low |
| Type confusion risk | Medium — both export `rustls::ClientConfig` (different versions) | Medium |
| Security advisory exposure | No current CVEs for either version | Low |
| Maintenance burden | Medium — two API patterns to remember | Medium |

## Options Evaluated

### Option A: Upgrade everything to rustls 0.23
- Requires `reqwest 0.11 → 0.12` (breaking: `ClientBuilder` API changed)
- Requires migrating all `rustls 0.21` usage to 0.23 provider-based API
- Effort: 3–5 days
- Risk: High — reqwest 0.12 may break proxy, multipart, or streaming behavior

### Option B: Remove rustls 0.21, migrate legacy code to rustls-ech
- Same breaking API changes as Option A, without reqwest upgrade
- Still need to refactor all `rustls::ClientConfig` construction
- Effort: 2–4 days
- Risk: Medium — internal TLS code changes only

### Option C: Defer (selected)
- Accept duplication until `reqwest 0.12` is required by another feature
- Binary bloat is acceptable (~500 KB in release build)
- No security advisories for either version at this time
- Effort: Zero (documentation only)
- Risk: Low — monitored via `cargo audit` / `cargo deny`

## Trigger Conditions for Revisit

Revisit this decision when ANY of the following occurs:
1. `reqwest 0.12` becomes required (e.g., for HTTP/3 client improvements, new proxy features)
2. A security advisory is published for `rustls 0.21` that is not backportable
3. Binary size becomes a constraint (embedded/mobile deployment)
4. `tokio-rustls 0.26` drops support for rustls 0.21 compatibility shims

## Monitoring

Run periodically:
```bash
cargo tree -d -p rustls  # show duplicate rustls versions
cargo audit              # check for security advisories
```

## Residual Risk Acceptance

Binary bloat and dual-API maintenance are accepted as lower priority than stability. The duplication is bounded to two crates (`rustls`, `webpki-roots`) and has no runtime performance impact.
