# MCP Interno — Roadmap de Optimización Expandido (V14.1+)
> Documento complementario al `MCP_INTERNO_ROADMAP.md` · Enfoque en Escalabilidad y Resiliencia

---

## 📋 Índice
1. [Análisis de Gaps y Dependencias](#1-análisis-de-gaps-y-dependencias)
2. [Timeline Expandido e Hitos](#2-timeline-expandido-e-hitos)
3. [Especificaciones Técnicas Detalladas](#3-especificaciones-técnicas-detalladas)
4. [KPIs y Criterios de Éxito](#4-kpis-y-criterios-de-éxito)
5. [Plan de Testing y Validación](#5-plan-de-testing-y-validación)
6. [Gestión de Riesgos y Mitigación](#6-gestión-de-riesgos-y-mitigación)
7. [Entregables y Estándares de Calidad](#7-entregables-y-estándares-de-calidad)

---

## 1. Análisis de Gaps y Dependencias
El roadmap original establece una base sólida pero presenta omisiones críticas para un entorno de producción:

*   **Gaps Técnicos:**
    *   **OOM via Regex:** No se define un límite de seguridad para el tamaño del output antes del filtrado semántico. Un output de 50MB de `Nmap` podría colapsar el hilo de ejecución.
    *   **Persistencia de Caché:** El uso de `moka` es volátil. Si el servicio se reinicia, se pierden los hallazgos previos, forzando re-escaneos costosos.
    *   **Negociación de Protocolo:** Falta un mecanismo para que el cliente MCP informe si soporta TONE/TONL antes de enviarlo.
*   **Dependencias Críticas:**
    *   **Hardware Detection:** La compresión debe ajustarse según la capacidad del host (CPU/RAM disponible).
    *   **Plugin Registry:** Dependencia total de la estabilidad del trait `Scanner` en `redteam_rust_core`.

---

## 2. Timeline Expandido e Hitos
Estimación basada en sprints de 2 semanas.

| Hito | Fase Relacionada | Descripción | Responsable |
|---|---|---|---|
| **M1: Alpha Compression** | Fase 1 & 4.1 | Implementación de `OutputFilter` y `SCRUBBER` en pipeline. | Lead Rust Dev |
| **M2: Persistent Intelligence** | Fase 2 | Integración de `moka` con fallback a SQLite para caché persistente. | Backend Eng |
| **M3: TONE Protocol** | Fase 3 | Implementación de `tone_encode` y negociación de headers. | AI Architect |
| **M4: Resilience & Stats** | Fase 5 & 6 | Dashboard de métricas y sistema de retry con backoff. | DevOps/SRE |

---

## 3. Especificaciones Técnicas Detalladas

### 3.1 — Capa de Filtrado (Fase 1)
*   **Buffer Limit:** Máximo 5MB para procesamiento regex. Outputs mayores se truncan preventivamente.
*   **Streaming Support:** Evaluar el procesamiento de líneas por flujo para reducir el footprint de memoria.

### 3.2 — Motor de Caché (Fase 2)
*   **Key Derivation:** `SHA256(plugin_id + target_canonical + config_hash)`.
*   **TTL Dinámico:** 30 min para info volátil, 24h para configuraciones estáticas.

### 3.3 — TONE Encoding (Fase 3)
*   **Header:** `#type:tone-v1;keys:$0:id,$1:sev`.
*   **Fallback:** Si el header `Accept-Encoding` no incluye `tone`, enviar JSON comprimido estándar.

---

## 4. KPIs y Criterios de Éxito
Para considerar una fase como completada:

1.  **Token Compression Ratio (TCR):** Reducción mínima del 40% en payloads de >20 findings.
2.  **Cache Hit Ratio (CHR):** >25% en sesiones de auditoría iterativa.
3.  **Latency Overhead:** El filtrado no debe añadir más de 50ms al tiempo total de respuesta.
4.  **Zero Leak Policy:** 100% de efectividad en el enmascaramiento de IPs/Credenciales reales en el output final.

---

## 5. Plan de Testing y Validación

### Casos de Uso Específicos:
*   **UC-01 (Heavy Load):** Ejecutar `Nuclei` con 500+ templates. Validar que el `MAX_CRITICAL` cap funciona y no hay OOM.
*   **UC-02 (Cache Collision):** Dos targets distintos con el mismo nombre DNS (en redes aisladas). Validar que la caché distingue por contexto de red.
*   **UC-03 (Anti-Hallucination):** Inyectar una API Key falsa en el output de un plugin. Validar que el `SCRUBBER` la elimina antes de llegar al cliente.

---

## 6. Gestión de Riesgos y Mitigación

| Riesgo | Impacto | Mitigación |
|---|---|---|
| **Regex DoS** | Alto | Timeouts estrictos (100ms) para cada operación de reemplazo regex. |
| **Inconsistencia de Datos** | Medio | Versionado de caché. Al actualizar un plugin, invalidar su caché asociada. |
| **Pérdida de Contexto AI** | Alto | Mantener siempre un "Resumen Ejecutivo" en texto plano incluso si el detalle está en TONE. |

---

## 7. Entregables y Estándares de Calidad

*   **Código:** 100% de cobertura en tests unitarios para `sanitizer.rs` y `tone.rs`.
*   **Documentación:** Swagger/OpenAPI actualizado para los endpoints SSE.
*   **Logs:** Implementación de `tracing` con niveles diferenciados (OPSEC vs Performance).
*   **Seguridad:** Auditoría interna de `fail-closed` design: si el filtro falla, el output no se envía.

---
_Documento generado para OsintUltimate V14.1 Performance Engineering._
