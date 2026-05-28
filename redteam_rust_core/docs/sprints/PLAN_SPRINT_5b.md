# Sprint 5b Plan: Quinn QUIC + HTTP/3 Full Client

## Objective
Build a production-grade QUIC transport client (`quinn`) and HTTP/3 client (`h3` + `h3-quinn`) that can perform **complete handshakes** and application-layer requests. The Sprint 5a `quic_forge.rs` only forged Initial packets (probe-only); Sprint 5b adds real connectivity.

**Out of scope (deferred to Sprint 5c/6):** AF_XDP RX (requires eBPF redirect program).

## Dependency Alignment

Current workspace uses `rustls = "0.21"`. The `quinn` and `h3` ecosystems must align:

| Crate | Version | rustls compat | Rationale |
|-------|---------|---------------|-----------|
| `quinn` | `0.10` | rustls 0.21 | Last quinn series using rustls 0.21 |
| `h3` | `0.0.6` | quinn 0.10 | HTTP/3 protocol implementation |
| `h3-quinn` | `0.0.6` | quinn 0.10 | Quinn transport adapter for h3 |

If we upgrade rustls later, quinn/h3 must be bumped together (Sprint 7+ tech debt).

## Architecture

### 1. `quinn_client.rs` — Full QUIC Transport Client

```rust
pub struct QuinnEvasionClient {
    endpoint: quinn::Endpoint,
    config: quinn::ClientConfig,
}

impl QuinnEvasionClient {
    /// Create client with system root CAs.
    pub fn new() -> Result<Self>;

    /// Connect to a QUIC server. Completes full TLS 1.3 handshake.
    pub async fn connect(&self, addr: SocketAddr, server_name: &str) -> Result<QuinnConnection>;

    /// Connect with a custom rustls::ClientConfig (for JA4 spoofing integration).
    pub async fn connect_with_tls(
        &self,
        addr: SocketAddr,
        server_name: &str,
        tls_config: rustls::ClientConfig,
    ) -> Result<QuinnConnection>;
}

pub struct QuinnConnection {
    conn: quinn::Connection,
}

impl QuinnConnection {
    /// Open a bidirectional stream.
    pub async fn open_bi(&self) -> Result<(SendStream, RecvStream)>;
    /// Graceful close.
    pub fn close(&self, error_code: VarInt, reason: &[u8]);
    /// Connection stats (rtt, packets sent/lost).
    pub fn stats(&self) -> ConnectionStats;
}
```

**Key design points:**
- `quinn::ClientConfig` in 0.10 wraps `rustls::ClientConfig`. We expose both default (system roots) and custom TLS config paths.
- Connection stats exposed for evasion telemetry (RTT helps time fragment attacks).
- No `#[cfg(target_os = "linux")]` gate — quinn is cross-platform.

### 2. `http3_client.rs` — HTTP/3 Client

```rust
pub struct Http3EvasionClient {
    quinn_client: QuinnEvasionClient,
}

impl Http3EvasionClient {
    pub fn new() -> Result<Self>;
    pub fn from_quinn(quinn_client: QuinnEvasionClient) -> Self;

    /// Perform an HTTP/3 GET.
    pub async fn get(&self, url: &str) -> Result<Http3Response>;

    /// Perform an HTTP/3 POST.
    pub async fn post(&self, url: &str, body: Bytes) -> Result<Http3Response>;

    /// Perform HTTP/3 request with custom headers (for probe fingerprinting).
    pub async fn request(
        &self,
        method: Method,
        url: &str,
        headers: HeaderMap,
        body: Option<Bytes>,
    ) -> Result<Http3Response>;
}

pub struct Http3Response {
    pub status: u16,
    pub headers: HeaderMap,
    pub body: Bytes,
}
```

**Key design points:**
- Uses `h3::client::Builder` + `h3_quinn::Connection`.
- URL parsing extracts host (for SNI/server_name) and path.
- Single connection per request for now (connection pooling deferred to Sprint 6).
- `reqwest`-like API surface for consistency with `ja4_http_client.rs`.

### 3. `quic_evasion.rs` — QUIC-Specific Evasion Strategies (Optional, time-permitting)

```rust
pub enum QuicEvasionStrategy {
    /// Send 0-RTT data on connection resume.
    ZeroRtt,
    /// Migrate to a new local address mid-connection.
    ConnectionMigration,
    /// Forge a Retry token to probe server statelessness.
    RetryTokenProbe,
}
```

**Time-boxed:** Only implement `ZeroRtt` if Sprint 5b core is complete early. Otherwise defer to Sprint 5c.

### 4. Orchestrator Integration

Add to `NetEvasionOrchestrator`:

```rust
/// Perform a full QUIC handshake + optional HTTP/3 request.
pub async fn quic_full_handshake(
    &self,
    target: SocketAddrV4,
    server_name: &str,
) -> Result<EvasionResult>;

/// Perform an HTTP/3 GET request.
pub async fn http3_request(
    &self,
    url: &str,
) -> Result<EvasionResult>;
```

Add to `NetEvasionStrategy`:
```rust
QuicFullHandshake,
Http3Request,
```

## Files to Create / Modify

| File | Action | Lines (est.) |
|------|--------|--------------|
| `Cargo.toml` | Add `quinn = "0.10"`, `h3 = "0.0.6"`, `h3-quinn = "0.0.6"` | +3 |
| `src/core/net_evasion/quinn_client.rs` | Create | ~250 |
| `src/core/net_evasion/http3_client.rs` | Create | ~200 |
| `src/core/net_evasion/quic_evasion.rs` | Create (optional) | ~150 |
| `src/core/net_evasion/mod.rs` | Add module declarations, enum variants | +5 |
| `src/core/net_evasion/orchestrator.rs` | Add `quic_full_handshake`, `http3_request` | +80 |

## Testing Plan

1. **Unit tests** (no network required):
   - `QuinnEvasionClient::new()` builds without error.
   - `Http3EvasionClient::new()` builds without error.
   - URL parsing for host/path extraction.
   - `rustls::ClientConfig` → `quinn::ClientConfig` conversion.

2. **Integration tests** (requires localhost QUIC server; skip in CI):
   - `test_quic_handshake_localhost` — spin up `quinn` server, client connects.
   - `test_http3_get_localhost` — h3 server + client GET.
   - Mark with `#[ignore]` if no local server available.

## Risk Register

| Risk | Mitigation |
|------|------------|
| `quinn 0.10` API differs significantly from latest docs (0.11) | Pin to 0.10 docs; test compile early |
| `h3-quinn 0.0.6` may have MSRV or edition conflicts | Test `cargo check` immediately after adding deps |
| rustls 0.21 config incompatible with quinn 0.10 expectations | Use `quinn::ClientConfig::with_root_certificates()` wrapper |
| HTTP/3 localhost testing is complex | Skip integration tests in CI; unit tests cover construction logic |

## Definition of Done

- [ ] `cargo test --lib` passes (189+ tests).
- [ ] `cargo clippy` clean.
- [ ] New files have module-level docs explaining QUIC / HTTP/3 evasion purpose.
- [ ] `orchestrator.rs` exposes `quic_full_handshake` and `http3_request`.
- [ ] CLAUDE.md updated with Sprint 5b status.
