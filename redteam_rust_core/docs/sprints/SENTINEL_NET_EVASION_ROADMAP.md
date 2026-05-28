# SENTINEL Net Evasion Engine — Sprint Roadmap

Module: `src/core/net_evasion/`
Baseline: Ptacek & Newsham (1998) + 2026 SOTA NGFW bypass

Auditor: Claude (code-auditor role). Ejecutor: Kimi/antigravity-cli.
Violaciones acumuladas: 21 (Sprint 7=13, 7.5=5, Sprint 11=2, Sprint 3-remediation=1)

---

## Estado Actual

| Sprint | Contenido | Estado | SHA / Nota |
|--------|-----------|--------|------------|
| **Sprint 1** | `packet_forge`, `raw_socket`, L2 parser | ✅ Completo | — |
| **Sprint 2** | L3 IP fragmentation (RFC 791): overlapping, tiny, TTL insertion | ✅ Completo | fix: ip_id + MF flag |
| **Sprint 3** | L4 TCP evasion: micro-seg, state desync, URG abuse, zero-window, TFO | ✅ Completo | SHA `5703882` |
| **Sprint 4** | JA4/JA4S active spoofing — Chrome 120 / Firefox 121 profiles | ⏳ Plan aprobado | — |
| **Sprint 5** | AF_XDP kernel-bypass + HTTP/3 + QUIC obfuscation | 🔲 Pendiente | — |
| **Sprint 6** | MASQUE (RFC 9298) + DoH3 tunneling + HTTPS Domain Fronting | 🔲 Pendiente | — |
| **Sprint 7** | ECH (RFC 9460) + TLS 1.3 0-RTT misuse + JA4 dynamic DB | 🔲 Pendiente | — |
| **Sprint 8** | Conjure / Refraction Networking (ISP-level censorship bypass) | 🔲 Pendiente | — |
| **Sprint 9** | Oblivious HTTP (RFC 9458) + metadata isolation | 🔲 Pendiente | — |
| **Sprint 10** | FwStress: State Table Exhaustion + CPU Exhaustion (`sovereign` feature) | 🔲 Pendiente | — |

---

## Sprint 4 — JA4/JA4S Active Spoofing

**Objetivo**: Craft TLS ClientHello handshakes whose JA4 fingerprint matches Chrome 120 / Firefox 121 to bypass NGFW fingerprint-based blocking (Palo Alto PAN-OS 11, Fortinet 7.4, Zscaler ZIA).

**Archivos**:

| # | Archivo | Acción |
|---|---------|--------|
| 1 | `src/core/net_evasion/ja4_spoofer.rs` | Nuevo — rustls config approximation |
| 2 | `src/core/net_evasion/tls_raw_forge.rs` | Nuevo — raw ClientHello builder (Tier 2) |
| 3 | `src/core/net_evasion/ja4_http_client.rs` | Nuevo — reqwest wrapper con JA4 spoofado |
| 4 | `src/core/net_evasion/orchestrator.rs` | Modificar — `ja4_evasion_request()` |
| 5 | `src/core/net_evasion/mod.rs` | Modificar — declarar módulos nuevos |
| 6 | `src/utils/ja4.rs` | Modificar — `parse_ja4()` + fix line 52 order bug |

**Deps a agregar**:
```toml
rustls = "0.21"   # verificar versión con: cargo tree -d rustls
```

**Design**:
- Tier 1: `rustls::ClientConfig` approximation → real HTTPS via `reqwest`
- Tier 2: raw ClientHello forge → fingerprint probe only (`fingerprint_probe()`)
- `extensions: Vec<(u16, Vec<u8>)>` — owned, sin lifetime issues
- GREASE: Tier 2 puede inyectar; Tier 1 (rustls) no. Limitación documentada.

**Bug fix requerido** (`ja4.rs:52`):
```rust
// Antes (incorrecto) — produce t13dh21516
format!("t{}{}{}{}{}", protocol, sni_type, alpn_prefix, ext_count, cipher_count)

// Después (correcto) — produce t13d1516h2
format!("t{}{}{}{}{}", protocol, sni_type, ext_count, cipher_count, alpn_prefix)
```

---

## Sprint 5 — AF_XDP + HTTP/3 + QUIC

**Objetivo**: Kernel-bypass packet injection (AF_XDP) para evadir hooks eBPF; HTTP/3 sobre QUIC para evadir middleboxes que solo inspeccionan TCP.

**Componentes clave**:
- `af_xdp_channel.rs` — AF_XDP socket, userspace L2 injection
- `quic_evasion.rs` — QUIC obfuscation (xquic / qboxer signatures)
- `http3_client.rs` — HTTP/3 con fingerprint limpio

**Prerequisitos**: `xdptools` / `libbpf`, `quinn` crate, eBPF program loader.
**Nota de deploy**: Solo en workers DigitalOcean (CAP_NET_RAW + BPF capabilities); NUNCA en Oracle.

---

## Sprint 6 — MASQUE + DoH3 + Domain Fronting

**Objetivo**: L4/L7 tunneling para exfiltrar tráfico a través de proxies HTTPS permitidos.

**Componentes clave**:
- `masque_tunnel.rs` — RFC 9298 CONNECT-UDP/IP tunnel
- `doh3_tunnel.rs` — DNS-over-HTTPS/3 data exfil channel
- `domain_front.rs` — HTTPS Domain Fronting (post-Cloudflare 2023 variant)
- `topology_prober.rs` — `traceroute_to_firewall()` para reemplazar `fw_hop_count=3` hardcoded en Sprint 3

**Sprint 6 también completa** Sprint 3 劣项: `fw_hop_count` TODO.

---

## Sprint 7 — ECH + TLS 1.3 0-RTT

**Objetivo**: Encrypted Client Hello (RFC 9460) para ocultar SNI del inspector; 0-RTT misuse para data exfil.

**Componentes clave**:
- `ech_client.rs` — ECH outer/inner ClientHello construction
- `tls13_0rtt.rs` — 0-RTT replay-tolerant data channel
- `ja4_database.rs` — Dynamic JA4 profile database (reemplaza hardcoded Sprint 4)

---

## Sprint 8 — Conjure / Refraction Networking

**Objetivo**: Bypass censura a nivel ISP usando estaciones de refracción en tráfico legítimo.

**Componentes clave**:
- `conjure_client.rs` — Covert channel a través de tráfico HTTPS permitido
- `refraction_station.rs` — Station selection + tagging

---

## Sprint 9 — Oblivious HTTP

**Objetivo**: Metadata isolation via Oblivious HTTP (RFC 9458) — separar identidad del cliente del contenido.

**Componentes clave**:
- `ohttp_client.rs` — OHTTP relay + gateway selection
- `bhttp_codec.rs` — Binary HTTP encoding (RFC 9292)

---

## Sprint 10 — FwStress (feature `sovereign`)

**Objetivo**: State table exhaustion + CPU exhaustion contra NGFW bajo control autorizado.

**Componentes clave**:
- `state_exhaustion.rs` — TCP half-open flood, connection table fill
- `cpu_exhaustion.rs` — Deep inspection compute overload

**ADVERTENCIA**: Ambos módulos compilados solo con `--features sovereign`. Doble gate requerido:
1. `allow_destructive_probes: true` en TacticalContext
2. `REDTEAM_DESTRUCTIVE=1` env var

**Deploy**: EXCLUSIVO en workers DigitalOcean. Jamás Oracle.

---

## Constraints del Proyecto

- **Raw socket / scanning**: SOLO workers DigitalOcean ephemeral. Oracle = ban inmediato.
- **Sprint discipline**: 1 stage por turn. Auditor veredicto entre stages.
- **Verification**: Siempre pegar output completo de `cargo check`, `clippy -D warnings`, `cargo test`.
- **Scope isolation**: Cambios fuera del sprint scope = VIOLACIÓN. Commit separado requerido.
