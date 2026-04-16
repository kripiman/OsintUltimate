# MCP Interno — Roadmap de Optimización
> `redteam_rust_core/src/core/mcp/` · Estado base analizado · V14.1

---

## Estado Actual (Baseline)

| Componente | Estado |
|---|---|
| `server.rs` — `handle_execute_plugin` | Devuelve texto plano sin comprimir |
| `sanitizer.rs` — `DataSanitizer` | Solo enmascara IPs/dominios. Sin filtrado semántico |
| Cache de ejecución | Ninguna. Cada llamada re-ejecuta el plugin completo |
| Serialización de findings | `format!("- [{}]: {}", severity, title)` — sin estructura |
| Anti-alucinación | Ninguna. El cliente recibe output crudo de herramientas |
| Métricas de sesión | Ninguna. Sin visibilidad de tokens consumidos |
| Failover | Ninguno. Si el plugin falla, retorna `Err` directo |

El `TieredAIRouter` y `ContextCompressor` ya existen en `core/ai/` pero el MCP no los usa en el pipeline de salida.

---

## Fase 1 — Compresión de Output en el Punto de Salida
**Prioridad: CRÍTICA · Impacto: Alto · Esfuerzo: Bajo**

### 1.1 — Filtro semántico de output de herramientas

**Archivo:** `sanitizer.rs`

Añadir `OutputFilter` que procese el texto crudo de cada plugin antes de enmascarar. El punto de inyección ya existe en `handle_execute_plugin`:

```rust
// Actual
let final_text = state.sanitizer.mask_output(&summary);

// Objetivo
let filtered = state.sanitizer.filter_tool_output(plugin_name, &summary);
let final_text = state.sanitizer.mask_output(&filtered);
```

Reglas por tipo de herramienta:

| Plugin | Ruido a eliminar | Señal a conservar |
|---|---|---|
| Nmap | líneas `SF:`, `Nmap done`, banners vacíos | puerto, servicio, versión, estado |
| Nuclei | líneas `[INF]`, `[WRN]`, timestamps | `[critical]`/`[high]`/`[medium]` + template ID |
| SQLMap | banners ASCII, `[INFO] testing`, progress bars | payload confirmado, DB type, tablas |
| Feroxbuster | líneas 404/403 masivas | 200/301/302 con tamaño relevante |
| Naabu | líneas de progreso | `host:port` confirmados |

Implementación: tabla `HashMap<&str, Vec<Regex>>` de patrones a eliminar por plugin. ~50 líneas.

### 1.2 — Integrar `ContextCompressor` existente

**Archivo:** `server.rs` — `handle_execute_plugin`

El `ContextCompressor` ya está implementado en `core/ai/compressor.rs`. El MCP no lo usa. Cambio mínimo:

```rust
// Actual — texto plano
for f in findings {
    summary.push_str(&format!("- [{}]: {}\n", f.severity, f.title));
}

// Objetivo — usar compressor existente
let compressed: Vec<_> = findings.iter()
    .map(|f| ContextCompressor::compress_finding(f, RouteLevel::Local))
    .collect();
let summary = serde_json::to_string(&compressed)?;
```

Esto activa truncación de bodies a 512 chars, filtrado de headers no-security, y scrubbing de datos sensibles — todo ya implementado.

---

## Fase 2 — Cache de Ejecución por Sesión
**Prioridad: ALTA · Impacto: Alto · Esfuerzo: Medio**

### 2.1 — Cache `(plugin_name, target_real)` con TTL

**Archivo:** `server.rs` — struct `McpServer`

Añadir cache `moka` (ya es dependencia del proyecto) al `McpServer`:

```rust
use moka::future::Cache;

pub struct McpServer {
    config: Arc<GlobalConfig>,
    sanitizer: Arc<DataSanitizer>,
    sessions: Arc<DashMap<String, mpsc::Sender<Event>>>,
    // NUEVO
    plugin_cache: Cache<String, String>, // key: "plugin:target_hash" → output comprimido
}
```

TTL recomendado: 30 minutos (operación activa). Si el mismo cliente MCP pide `NmapScanner` sobre el mismo target dos veces en la misma sesión, la segunda llamada retorna el resultado cacheado sin re-ejecutar Nmap.

Clave de cache: `SipHash(plugin_name + target_real)` — mismo patrón que `TieredAIRouter.calculate_finding_cache_key`.

### 2.2 — Header de cache en respuesta

Añadir metadato al `CallToolResult` para que el cliente sepa si el resultado es fresco o cacheado:

```
[CACHED: NmapScanner/TARGET_1 · 8min ago · ~1240 tokens saved]
```

---

## Fase 3 — TONE Encoding para Arrays de Findings
**Prioridad: MEDIA · Impacto: Medio · Esfuerzo: Medio**

### 3.1 — Serialización TONE cuando findings > 10

**Archivo:** `server.rs` — `handle_execute_plugin`

Para scans con muchos findings (Nuclei típicamente 20-100+), el JSON estándar repite claves en cada objeto. TONE elimina esa repetición:

```
// JSON estándar — 50 findings × ~60 chars/finding = ~3000 chars
[{"sev":"high","cat":"injection","id":"sqli-001"}, ...]

// TONE — header fijo + filas densas
#keys $0:sev,$1:cat,$2:id
[50]{$0,$1,$2}:
  high,injection,sqli-001
  medium,xss,xss-042
  ...
```

Implementar `tone_encode(findings: &[Value]) -> String` en un nuevo `utils/tone.rs`. Activar solo cuando `findings.len() > 10`.

El cliente MCP (Claude, GPT-4) puede parsear TONE porque el header es autodescriptivo. Si el cliente no lo soporta, fallback a JSON comprimido.

---

## Fase 4 — Anti-Alucinación: Validación de Contexto
**Prioridad: ALTA · Impacto: Alto · Esfuerzo: Medio**

### 4.1 — Scrubbing de output antes de enviar al cliente

**Archivo:** `sanitizer.rs`

El `SCRUBBER` de `core/ai/scrubber.rs` ya elimina credenciales, tokens, y datos sensibles del contexto AI. El MCP no lo aplica al output de plugins.

Añadir llamada a `SCRUBBER.scrub(&filtered)` en el pipeline de `mask_output`. Esto previene que el cliente MCP reciba:
- API keys en outputs de GitLeaks/TruffleHog
- Hashes de contraseñas en outputs de Impacket
- Tokens JWT en outputs de Burp/ZAP

### 4.2 — Prefijo de confianza por tipo de finding

Añadir prefijo semántico al output para que el cliente AI no alucine sobre el estado de verificación:

```
[UNVERIFIED] - [high]: SQL Injection en /login
[VERIFIED]   - [critical]: RCE via CVE-2024-XXXX (PoC ejecutado)
[POTENTIAL]  - [medium]: Open Redirect (requiere validación manual)
```

El campo `finding.verified` ya existe en el modelo. Solo hay que usarlo en el formato de salida.

### 4.3 — Límite de findings por severidad en output

Prevenir context overflow cuando un scan retorna 200+ findings de baja severidad:

```rust
// Cap por severidad para no saturar el contexto del cliente
const MAX_CRITICAL: usize = 20;
const MAX_HIGH: usize = 30;
const MAX_MEDIUM: usize = 20;
const MAX_LOW: usize = 10;
// + resumen: "N findings adicionales de severidad LOW omitidos"
```

---

## Fase 5 — Métricas de Sesión y Visibilidad
**Prioridad: MEDIA · Impacto: Medio · Esfuerzo: Bajo**

### 5.1 — Contador de tokens estimados por sesión

**Archivo:** `server.rs` — struct `McpServer`

Añadir `AtomicU64` de tokens estimados por sesión (estimación: `chars / 3.5`). Reportar en cada respuesta como comentario al final:

```
[SESSION: 3 calls · ~4,820 tokens out · 2 cache hits · 1,240 tokens saved]
```

### 5.2 — Tool `mcp_session_stats`

Añadir una segunda herramienta al `tools/list` para introspección de sesión:

```json
{
  "name": "mcp_session_stats",
  "description": "Retorna métricas de la sesión MCP actual: tokens consumidos, cache hits, plugins ejecutados."
}
```

Sin argumentos. Retorna JSON con el estado de la sesión. Permite al cliente AI decidir si debe comprimir su contexto antes de continuar.

---

## Fase 6 — Failover y Resiliencia
**Prioridad: MEDIA · Impacto: Medio · Esfuerzo: Bajo**

### 6.1 — Retry con backoff en `handle_execute_plugin`

Actualmente si `p.scan(&host).await` falla, retorna error inmediato. Añadir retry con backoff exponencial (2 intentos, 1s/2s delay) para errores transitorios (timeout, proceso no encontrado).

### 6.2 — Fallback a resultado cacheado en fallo

Si el plugin falla y existe un resultado cacheado (aunque expirado), retornarlo con prefijo `[STALE CACHE]` en lugar de error. Mejor contexto degradado que error vacío.

---

## Orden de Implementación Recomendado

```
Fase 1.1 → Fase 1.2 → Fase 4.1 → Fase 4.2 → Fase 2.1 → Fase 2.2
   ↓            ↓           ↓           ↓           ↓
 50 líneas   10 líneas   5 líneas   10 líneas   40 líneas
 sanitizer   server      sanitizer   server      server+moka
```

Las fases 3, 4.3, 5, y 6 son mejoras incrementales una vez el pipeline base está comprimido.

---

## Archivos Afectados

| Archivo | Cambio |
|---|---|
| `core/mcp/sanitizer.rs` | + `filter_tool_output()`, + `SCRUBBER` integration |
| `core/mcp/server.rs` | + `plugin_cache`, + `ContextCompressor` en pipeline, + caps por severidad |
| `utils/tone.rs` | NUEVO — `tone_encode()` para arrays de findings |
| `core/mcp/protocol.rs` | Sin cambios |
| `core/mcp/mod.rs` | + re-export de nuevos módulos si aplica |

Ningún cambio en plugins, modelos, ni `TieredAIRouter`. Todo el trabajo está en la capa MCP.
