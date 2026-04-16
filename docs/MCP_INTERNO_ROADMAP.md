# MCP Interno — Roadmap de Optimización
> `redteam_rust_core/src/core/mcp/` · **V14.5 — Todas las fases completadas**

---

## Estado Actual (Post-Implementación)

| Componente | Estado V14.5 |
|---|---|
| `server.rs` — `handle_execute_plugin` | Pipeline completo: filtro → compressor → TONE → mask |
| `sanitizer.rs` — `OutputFilter` | V2: arquitectura `FilterStrategy` (Deny/Allow), lógica acumulativa |
| Caché de ejecución | RAM (moka, 30min TTL) + SQLite persistente, dual-key SHA256 |
| Serialización de findings | TONE V1 (5 campos) con negociación `support_tone`, fallback JSON |
| Anti-alucinación | Trust prefixes, Severity Caps, SCRUBBER mandatorio todos los niveles |
| Métricas de sesión | AtomicU64 + SQLite histórico + herramienta `mcp_get_stats` |
| Failover | Backoff conservador (2s/5s/10s) + stale cache fallback |

---

## Fase 1 — Compresión de Output ✅ COMPLETADO (HARDENED V2)

### 1.1 — OutputFilter V2

**Archivo:** `sanitizer.rs`

Pipeline implementado en `filter_tool_output`:

```rust
// Pipeline actual
let filtered = self.filter.filter(plugin_name, text);   // semántico
let scrubbed = SCRUBBER.scrub(&filtered);               // secretos
// fail-closed si scrubbed vacío sobre input no vacío
```

Arquitectura `FilterStrategy` con dos modos:

| Estrategia | Plugins | Lógica |
|---|---|---|
| `Deny` | Feroxbuster, Naabu, Httpx, TruffleHog | Elimina líneas que matcheen regex de ruido |
| `Allow` | SqlMap | Conserva solo líneas con señal de explotación confirmada |

Reglas genéricas acumulativas (siempre activas en modo `Deny`):
- Progress bars: `^\s*\[[\s#=\.]+\]\s*\d+%`
- Separadores visuales: `^[\s=\-_+]{10,}$`
- Boilerplate legal: `(?i)^\s*(?:copyright|all rights reserved|license)`

Cobertura real por plugin (basada en auditoría del output de cada binario):

| Plugin | Estrategia | Detalle |
|---|---|---|
| `FeroxbusterScanner` | Deny | `^\s*(?:4\d{2}\|5\d{2})\s+` — columna de status, no substring. Preserva `/error404handler` con status 200. |
| `NaabuScanner` | Deny | Banner Go-PD + `[INF]/[WRN]/[ERR]`. Conserva `host:port`. |
| `HttpxScanner` | Deny | Motor ProjectDiscovery idéntico a Naabu. |
| `TruffleHogScanner` | Deny | Progress bars y banners. Conserva líneas de hallazgo. |
| `SqlMapScanner` | Allow | Allowlist: `injectable`, `retrieved`, `fetching`, `DBMS`, `database:`, `table:`, `column:`, `vulnerable`, `payload`. |

Plugins **sin reglas** (parsean JSON/XML antes de llegar al MCP — no necesitan filtrado):
Nmap (`parse_nmap_xml`), Nuclei (`-jsonl`), FFuf (`-of json`), Katana (`-jsonl`), WhatWeb (`--log-json`), Arjun (`-oJ`), Gitleaks (`--report-format json`), SovereignRecon (API REST directa).

### 1.2 — ContextCompressor integrado

`ContextCompressor::compress_finding(f, RouteLevel::Local)` aplicado a todos los findings antes de serializar. Trunca bodies a 512 chars, filtra headers no-security. Scrubbing mandatorio en todos los `RouteLevel` (bypass de Local eliminado).

---

## Fase 2 — Caché de Ejecución ✅ COMPLETADO (HARDENED)

- Dual-layer: RAM (moka, 30min) → SQLite (persistente).
- Clave: `SHA256(plugin + target + config_salt)` con retrocompatibilidad legacy.
- Tabla `plugin_cache` creada en schema de `SqliteSink` (gap G1 cerrado).
- Headers de respuesta: `[CACHED: RAM]`, `[CACHED: DISK]`, `[CACHED: LEGACY_RAM]`, `[CACHED: LEGACY_DISK]`.

---

## Fase 3 — TONE Encoding ✅ COMPLETADO (HARDENED)

- Header: `#type:tone-v1;keys:$0:id,$1:sev,$2:cat,$3:conf,$4:summary`
- Activación: `support_tone=true` OR `findings.len() > 10`
- Sanitización de delimitadores `|` y `\n` en cada campo.
- Test unitario corregido para validar 5 campos (gap G2 cerrado).

---

## Fase 4 — Anti-Alucinación ✅ COMPLETADO (HARDENED)

- `SCRUBBER` mandatorio en `filter_tool_output` (post-filtrado semántico).
- Trust prefixes `[VERIFIED]`/`[POTENTIAL]` desde `finding.evidence.verified`.
- Severity Caps: Critical:20, High:30, Medium:20, Low/Info:10.

---

## Fase 5 — Métricas ✅ COMPLETADO (PROFESIONAL)

- `AtomicU32/U64` para `total_calls`, `cache_hits`, `tokens_saved`, `bytes_processed`.
- Carga de métricas históricas desde SQLite al arranque del servidor.
- Herramienta `mcp_get_stats` con estimación de coste USD (`tokens * $0.000015`).

---

## Fase 6 — Resiliencia ✅ COMPLETADO (PROFESIONAL)

- Retry loop: 3 intentos, backoff 2s/5s/10s.
- Stale fallback: si el plugin falla y existe caché (aunque expirada), retornar con `[MODO_RESILIENCIA: DATOS_HISTÓRICOS]`.

---

## Fase 7 — Auditoría y Corrección de Gaps ✅ COMPLETADO (HARDENED V2)

Gaps identificados y cerrados tras revisión del código real:

| ID | Gap | Archivo | Fix |
|---|---|---|---|
| G1 | Tabla `plugin_cache` ausente del schema | `sink.rs` | `CREATE TABLE IF NOT EXISTS plugin_cache` añadida |
| G2 | Test TONE validaba 4 campos, header genera 5 | `tone.rs` | Assertion actualizada a `[N]{$0,$1,$2,$3,$4}:` |
| G3 | Scrubbing omitido en `RouteLevel::Local` | `compressor.rs` | Bypass eliminado, scrubbing mandatorio |
| G4 | Genéricas no acumulaban con específicas | `sanitizer.rs` | Lógica acumulativa en rama `Deny` |
| G5 | Feroxbuster: falso positivo en URLs con "404" | `sanitizer.rs` | Regex de columna de status, no substring |
| G6 | SQLMap: denylist perdía señal bajo `[INFO]` | `sanitizer.rs` | Reemplazado por `FilterStrategy::Allow` |
| G7 | Naabu, Httpx, TruffleHog sin reglas | `sanitizer.rs` | Reglas específicas implementadas |

---

## Archivos Modificados

| Archivo | Cambios |
|---|---|
| `core/mcp/sanitizer.rs` | OutputFilter V2: `FilterStrategy`, lógica acumulativa, 5 plugins, 6 tests |
| `core/mcp/server.rs` | Pipeline completo, caché dual-layer, métricas, retry, `mcp_get_stats` |
| `core/sink.rs` | Tablas `plugin_cache` y `mcp_stats` en schema SQLite |
| `utils/tone.rs` | TONE V1 con 5 campos, sanitización de delimitadores, test corregido |
| `core/ai/compressor.rs` | Scrubbing mandatorio eliminando bypass `RouteLevel::Local` |
