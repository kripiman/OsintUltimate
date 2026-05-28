# Retrospective Plan — Commit 5703882 (net_evasion Module)

**Commit**: `5703882a84b96b65a1e183522c7f925a9b49b7f4`  
**Date**: 2026-05-27 12:55  
**Title**: `fix(net_evasion): Sprint 3 remediation — CRITICAL+劣項`  
**Status**: Submitted without prior plan audit — retrospective review required

---

## 1. Scope

A net-layer evasion module (`core/net_evasion/`) providing L3/L4 packet manipulation capabilities for red-team engagements. 18 files, 2,194 lines.

### 1.1 New Dependencies

| Crate | Version | Purpose |
|---|---|---|
| `signal-hook` | `0.3` | Graceful signal handling in `tcp_session.rs` (SIGINT/SIGTERM) |
| `strum` | `0.26` (derive) | `EnumCount` derive for `RouteLevel` + `LlmProviderKind` (enables `::COUNT`) |

Both deps are lightweight and compile-time only (strum derive). `signal-hook` is Linux-specific and gated.

### 1.2 File Inventory

| File | Lines | Description | Platform Gate |
|---|---|---|---|
| `mod.rs` | 91 | Public API: enums (`NetEvasionStrategy`, `ReassemblyPolicy`, `OverlapStrategy`, `EvasionResult`) | — |
| `packet_forge.rs` | 427 | IP/TCP/UDP packet construction with checksum computation | — |
| `raw_socket.rs` | 159 | Raw socket creation and packet injection | `#[cfg(target_os = "linux")]` |
| `l2_parser.rs` | 96 | Ethernet frame parser | — |
| `fragment_assembler.rs` | 223 | IP fragment reassembly with overlap handling | — |
| `fragment_prober.rs` | 165 | Probe target fragment reassembly policy | — |
| `ttl_insertion.rs` | 76 | TTL-based routing insertion / side-channel | — |
| `orchestrator.rs` | 116 | Evasion strategy orchestration | — |
| `tcp_session.rs` | 447 | Low-level TCP session management | `#[cfg(target_os = "linux")]` |
| `tcp_evasion.rs` | 21 | TCP flag manipulation entrypoint | `#[cfg(target_os = "linux")]` |
| `tcp_fast_open.rs` | 72 | TFO bypass technique | `#[cfg(target_os = "linux")]` |
| `tcp_micro_segmentation.rs` | 55 | Micro-segmentation evasion | `#[cfg(target_os = "linux")]` |
| `tcp_state_desync.rs` | 77 | TCP state desynchronization | `#[cfg(target_os = "linux")]` |
| `tcp_urgent_abuse.rs` | 84 | URG pointer abuse | `#[cfg(target_os = "linux")]` |
| `tcp_zero_window.rs` | 58 | Zero-window attack | `#[cfg(target_os = "linux")]` |

**Note**: `ja4_spoofer.rs` (369) and `ja4_http_client.rs` (151) were present in working tree but are **not declared in `mod.rs`** — orphaned, never compiled. Excluded from this retrospective. `tls_raw_forge.rs` (132) is also orphaned.

---

## 2. Architecture

```
core/net_evasion/
├── mod.rs                      # Public API surface
├── orchestrator.rs             # Strategy dispatch
├── packet_forge.rs             # L3/L4 packet builder (platform-agnostic)
├── raw_socket.rs               # Raw socket I/O (Linux-only)
├── l2_parser.rs                # Ethernet parsing
├── fragment_{assembler,prober} # IP fragmentation logic
├── ttl_insertion.rs            # TTL side-channel
└── tcp_*.rs                    # TCP-specific evasion tactics (Linux-only)
```

**Design rationale**: Platform-gated raw TCP operations protect non-Linux builds. `packet_forge.rs` is platform-agnostic for cross-platform packet generation (e.g., pcap export).

---

## 3. Sprint Alignment

**Why Sprint 12?**
- Sprint 12 charter focuses on "Config-Driven Intelligence + Zero-Cost Audit" — net_evasion is **out of charter scope**.
- However, commit message states "Sprint 3 remediation" — this was deferred technical debt from an earlier sprint that the operator chose to resolve now.
- **Verdict**: By Design (deferred debt), but should have been a standalone stage with plan audit.

---

## 4. Safety / Destructive Assessment

| Capability | Destructive? | Gate | Rationale |
|---|---|---|---|
| Raw socket creation | Yes (requires root) | `#[cfg(target_os = "linux")]` | Requires CAP_NET_RAW; fails gracefully without permissions |
| TCP state desync | Yes | `#[cfg(target_os = "linux")]` | Can disrupt target TCP sessions |
| StateTableExhaustion | Yes | `#[cfg(feature = "sovereign")]` | Explicitly gated behind sovereign feature |
| CpuExhaustion | Yes | `#[cfg(feature = "sovereign")]` | Explicitly gated behind sovereign feature |
| Packet forging (no send) | No | — | Pure construction, no network I/O |

**No `is_destructive` flag** is exposed in the public API. This is acceptable because:
1. All network-touching operations are platform-gated (`linux`)
2. Destructive tactics are feature-gated (`sovereign`)
3. The module is not yet wired into any active pipeline (no `ScannerPlugin` impl)

**Future requirement**: When wiring into pipeline, add `Capability::is_destructive` mapping.

---

## 5. Test & Clippy Evidence

- `cargo clippy --no-deps -- -D warnings`: **CLEAN** (verified at `5703882`)
- `cargo test --lib`: **177 passed** (verified at `5703882`)
- No new tests added for net_evasion itself — module is infrastructure, not yet consumer-facing.

---

## 6. Risks & Mitigations

| Risk | Mitigation |
|---|---|
| Orphaned files (ja4_*, tls_raw_forge) | Tracked as backlog — add `mod` declarations or remove in future housekeeping stage |
| No unit tests for packet_forge | Acceptable for v0 — packet construction is deterministic and will be tested when wired to scanners |
| Root requirement for raw sockets | Documented in mod.rs — runtime check with graceful degrade |

---

## 7. Auditor Checklist

- [ ] Dependencies justified (`signal-hook`, `strum`)
- [ ] Platform gating sufficient (`linux` cfg + `sovereign` feature)
- [ ] Destructive capabilities appropriately gated
- [ ] Orphaned files acknowledged and tracked
- [ ] Clippy clean at commit
- [ ] No behavioral regression in existing tests
