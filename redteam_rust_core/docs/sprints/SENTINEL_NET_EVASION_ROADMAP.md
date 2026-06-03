# SENTINEL Net Evasion Engine — Sprint Roadmap

Module: `src/core/net_evasion/`
Baseline: Ptacek & Newsham (1998) + 2026 SOTA NGFW bypass

Auditor: Claude (code-auditor role). Ejecutor: Kimi/antigravity-cli.
Violaciones acumuladas: 24 (Sprint 7=13, 7.5=5, Sprint 11=2, Sprint 3-remediation=1, Stage-C false-report=1, bundling=1)

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

---

# ADDENDUM — Auditoría de Vigencia Técnica 2026

> Auditor: Claude (code-auditor role). Fecha: 2026-05-30.
> Estado: corrección a evaluación "Técnicas vigentes 2026" presentada por ejecutor.
> Naturaleza: documental (no toca código). Cutoff de conocimiento auditor: Ago-2025 — el estado de *despliegue* 2026 no es verificable; los hechos técnicos/históricos sí.

## A. Divergencia Roadmap-vs-Ejecución (hallazgo de auditoría)

La tabla de "Estado Actual" (arriba) describe el **plan original**. La ejecución real divergió en numeración y contenido:

| Sprint | Roadmap original | Ejecución real | Nota |
|--------|------------------|----------------|------|
| 7 | ECH + 0-RTT + JA4 dynamic DB | ECH client + TLS 1.3 0-RTT over TCP | ✅ parcial (JA4 DB no hecho) |
| 8 | Conjure / Refraction Networking | ECH DNS fetcher (`ech_dns_fetcher.rs`) | ⚠️ contenido distinto |
| 9 | Oblivious HTTP (RFC 9458) | h2c probe + HTTP request smuggling | ⚠️ contenido distinto |
| 10 | FwStress (sovereign, DoS) | Probe→Finding integration (en curso) | ⚠️ contenido distinto |

**Implicación**: Conjure, OHTTP y FwStress del plan original **NO ejecutados**. La numeración de sprint ya no mapea al roadmap. Violaciones acumuladas: roadmap dice 21, `CLAUDE.md` raíz dice **22** — usar 22.

## B. Correcciones fácticas a la evaluación 2026

| # | Afirmación evaluada | Veredicto | Corrección |
|---|---------------------|-----------|------------|
| 1 | "ECH (RFC 9460)" | ❌ Impreciso | RFC 9460 = registros DNS **SVCB/HTTPS** únicamente. ECH = `draft-ietf-tls-esni` (draft del TLS WG, no RFC completo a cutoff). RFC 9460 solo **transporta** el `ECHConfig` vía `SvcParamKey=5`. Confunde contenedor con contenido. Error arrastrado desde Sprint 7. |
| 2 | CONTINUATION flood "DoS / potencial RCE" | ❌ Overclaim | CONTINUATION flood (B. Nowotarski, Abr-2024) = **solo DoS** (agotamiento memoria/CPU por frames CONTINUATION sin HEADERS terminador). Ningún writeup serio reclama RCE. `CVE-2024-27983` = variante **Node.js** específica; el flood tuvo CVEs múltiples por implementación (Apache httpd, Envoy, Go net/http, etc.). |
| 3 | Browser-in-the-Browser "2024-2025" | ❌ Mal fechado | BitB = **mr.d0x, 2022**. Es UI phishing (iframe falso de ventana OAuth). "BitB + ECH" **no es técnica establecida** — especulación. Además phishing = **fuera de scope** `net_evasion`. Descartar del roadmap. |
| 4 | TLS 1.3 0-RTT vigente | ✅ Correcto | Estándar consolidado. Replay surface real. |
| 5 | HTTP Request Smuggling + HTTP/2→1.1 downgrade vigente | ✅ Correcto | Investigación continua Kettle/PortSwigger. |
| 6 | h2c desync útil en proxy mal configurado | ✅ Correcto | Bishop Fox 2020. Legacy pero válido. |
| 7 | Rapid Reset `CVE-2023-44487` | ✅ Correcto | L7 DDoS, Oct-2023, ya mitigado en stacks 2026. |
| 8 | OHTTP "RFC 9458" | ✅ Correcto | Fecha y RFC correctos. |

## C. Error estratégico — "novedad 2025" ≠ "rentable bug bounty"

Las 3 técnicas recomendadas como "más rentables para bug bounty" son **DoS/evasión → los programas no las pagan**:

| Recomendada | Tipo real | Payout bug bounty |
|-------------|-----------|-------------------|
| CONTINUATION flood | DoS | ❌ DoS out-of-scope en ~todo HackerOne/Bugcrowd |
| QUIC fingerprint rotation | Evasión de tráfico | ❌ No es vulnerabilidad; sin bounty directo |
| CT logs + ECH correlation | Recon/OSINT | ❌ Informativo; no paga |

Son **ejes distintos**: novedad técnica vs rentabilidad en programa. DoS excluido de scope en la mayoría de programas; peor, un flood puede **tumbar el target → baneo del programa**.

### Rentables reales faltantes (web-layer, en scope)

1. **Web Cache Deception / Poisoning** — Kettle 2024; paga alto; en scope casi siempre.
2. **HTTP/2 downgrade desync avanzado** — alto ROI, PERO **NO reusa `http_smuggle.rs`** (corrección 2026-06-01). Requiere forge de frames HTTP/2 + encoder HPACK propio (~300-500 LOC, módulo dedicado tipo `tls_raw_forge.rs`). El crate `h2` es compliant RFC 9113 y **rechaza** las malformaciones necesarias (H2.TE/H2.CL/CRLF) → no sirve. Raw TCP no puede expresar requests H2 post-upgrade (HPACK binario). Tratar como **sprint propio**, no como stage barato. Stage B (H2Preface) ya agotó la señal raw-TCP.
3. **mTLS pinning bypass** — alto valor en target mobile/API; en scope.

## D. Constraint de seguridad (vinculante)

Técnicas destructivas (CONTINUATION flood, Rapid Reset, QUIC flood) **NO** son probes normales:

1. Requieren `feature sovereign` (compilación aislada).
2. Doble gate: `allow_destructive_probes: true` + `REDTEAM_DESTRUCTIVE=1`.
3. **Ejecución EXCLUSIVA en workers DigitalOcean ephemeral — JAMÁS Oracle** (ban inmediato de cuenta).

**Detección acotada ≠ flood.** Verificar si un server acepta CONTINUATION sin límite se hace con test **bounded** (unos pocos frames), no con flood. No confundir un *probe de detección* con un *ataque de agotamiento*.

## E. Dirección recomendada Sprint 10 Stage B+

| Opción | Tipo | Scope bounty | Gating | Recomendación |
|--------|------|--------------|--------|---------------|
| Web Cache Deception | Vuln web | ✅ En scope | Normal | 🟢 **Prioridad** — HTTP/1.1 puro, reusa `reqwest`, ~100-150 LOC |
| mTLS pinning bypass | Vuln mobile/API | ✅ En scope | Normal | 🟢 Alto valor si hay target mobile |
| HTTP/2 downgrade desync | Vuln web | ✅ En scope | Normal | 🟠 Alto ROI pero **sprint propio** — frame forge H2 + HPACK (~300-500 LOC), NO stage barato (corrección 2026-06-01) |
| CONTINUATION (detección acotada) | Detección | ⚠️ DoS marginal | sovereign + DO | 🔴 Solo si gated, no flood |
| FwStress (roadmap original S10) | DoS | ❌ Out-of-scope | sovereign + DO | 🔴 No para bug bounty |

**Veredicto auditor (rev. 2026-06-01)**: para Stage C barato priorizar **Web Cache Deception** (HTTP/1.1, reusa `reqwest`) o **mTLS bypass**. HTTP/2 desync es alto ROI pero NO es extensión de `http_smuggle.rs` — requiere forge H2+HPACK propio (el crate `h2` compliant no sirve); tratar como sprint dedicado. Evitar floods DoS como stage normal; si se implementan, `sovereign` aparte, gated, DO-only.

---

## F. Engine Debt Log — Sprint 11 Stage C (2026-06-03)

### Commits verificados (auditor raw ✅)

| SHA | Ticket | Scope | Tests |
|-----|--------|-------|-------|
| `191f1b6` | ENGINE-TIMEOUT-001: `execute_safe_scan` bounded `min(2×expected, 600s)` | `dispatch.rs` | cargo check ✅ |
| `ab60a64` | ENGINE-TIMEOUT-002: `check_dependencies` bounded 30s | `dispatch.rs` | 249/0 raw ✅ |
| `ab60a64` | DB-BUDGET-001: UUID key + teardown in `test_database_budget_sync` | `api_budget.rs` | live Postgres ✅ |

**Full suite**: 249 passed / 0 failed / 8 ignored — verified RAW (13 suites, all `test result: ok`).

### Disciplina (violations +1)

- **V24 — Bundling** (`ab60a64`): ENGINE-TIMEOUT-002 + DB-BUDGET-001 = dos tickets no relacionados en un commit. Violación L145 (`Commit separado requerido`). Cuenta: 24.
- **RTK-WARN (no cuenta)**: RTK colapsó 13 suites en 1 línea sintética, ocultando `test result:` individuales. Distrust correcto — siempre verificar raw para output de grado verificación.

### Stage C — DEGRADED · bloqueador intacto

| Condición | Estado |
|-----------|--------|
| Toolchain (nuclei/dnsx/httpx/kr) presente | ❌ Ausente en este host |
| `golden_baseline.json` findings > 0 en disco | ❌ `[]` — no commitear |
| `DEGRADED` levantado | ❌ Permanece |
| Worker DO con toolchain completo | ⏳ Requerido per roadmap + Oracle-ban |

Estos 3 commits = deuda de engine independiente (timeouts + test DB). **NO** cierran Stage C. Stage C cierra únicamente cuando artefacto `golden_baseline.json` con findings > 0 reales aterrice en disco desde worker con nuclei+kiterunner+dnsx instalados.
