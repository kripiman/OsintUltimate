# TLS Impersonation Crate Selection Decision

This document surveys the available alternatives to the yanked `rquest` crate to resolve the TLS impersonation and JA3/JA4 fingerprinting blocker in the `redteam_rust_core` reconnaissance and scanner pipeline.

## Evaluation Matrix

| Metric | Option 1: `wreq` (w/ `wreq-util`) | Option 2: `reqwest-impersonate` | Option 3: `ja-tools` (w/ custom `rustls`) |
| :--- | :--- | :--- | :--- |
| **Primary Role** | Full HTTP Client (Browser Emulation) | Full HTTP Client (Browser Emulation) | TLS Fingerprint Parroting Tool |
| **API Parity** | High (Hard fork of `reqwest`) | High (Fork of `reqwest`) | Low (Requires custom HTTP engine / raw bytes) |
| **Maintenance** | Active (Latest: v5.3.0) | Mostly unmaintained / experimental forks | Low activity (Tied to specific `rustls` versions) |
| **GitHub Stars** | ~811 | Varies by fork (~100 max) | ~80 (XOR-op/ja-tools) |
| **License** | Apache-2.0 | MIT / Apache-2.0 | MIT |
| **Browser Profiles**| Chrome, Firefox, Safari (via `wreq-util`) | Chrome, Safari, Firefox, Edge, OkHttp | Custom (Must construct TLS client hello extension arrays) |
| **Dependency Risk** | Symbol conflicts with `openssl-sys` (uses BoringSSL) | Heavy reliance on patched hyper/h2 crates | Forked/patched `rustls` dependency required |
| **LOC Wrapper Cost**| Low (~50-80 lines in HTTP client adapter) | Low (~50-80 lines in HTTP client adapter) | Extremely High (2000+ lines for client wrapper) |

---

## Detailed Analysis

### 1. Option 1: `wreq` (Recommended)
`wreq` is currently the most robust and production-ready option for high-fidelity TLS and HTTP/2 browser emulation in the Rust ecosystem.
*   **Pros**:
    *   Maintains the familiar `reqwest` builder patterns, minimizing transition diffs in `http_client.rs`.
    *   Excellent support for JA3, JA4, and HTTP/2 settings matching.
    *   No patched `hyper`/`h2` dependency hell.
*   **Cons**:
    *   Uses BoringSSL. If other parts of the workspace compile against OpenSSL, symbol conflicts can occur. *Mitigation: Enable `prefix-symbols` feature or enforce pure rustls/boring separation.*

### 2. Option 2: `reqwest-impersonate`
An early prototype for browser emulation built on top of `reqwest` forks.
*   **Pros**: Fills the exact same API footprint as our original implementation.
*   **Cons**: Mostly abandoned or fragmented across several experimental forks. Requires cargo `[patch]` directives for hyper/h2, leading to fragile build matrix integration.

### 3. Option 3: `ja-tools` & Custom `rustls`
A low-level approach where we modify the ClientHello bytes directly using XOR-op's `ja-tools` utility.
*   **Pros**: Zero dependency on BoringSSL or OpenSSL. Pure Rust.
*   **Cons**: Extremely complex. Requires a custom fork of `rustls` to override the ClientHello. We would have to build a complete HTTP client wrapper from scratch to manage connection pools, cookies, redirects, and proxies, making it infeasible under the LOC budget.

---

## Selection Decision

**Winner**: **Option 1: `wreq`**

We will integrate `wreq` and `wreq-util` behind the `tls-impersonation` feature flag. To prevent linking issues with `openssl`, the crate will be configured with the necessary features to isolate BoringSSL symbols, ensuring compatibility with target platforms.
