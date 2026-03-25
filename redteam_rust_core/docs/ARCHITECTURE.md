# 🏗️ Arquitectura Técnica OsintUltimate v3.0

> **Motor de Evaluación de Red Team de Alto Rendimiento, Asíncrono y Autónomo**

Este documento detalla el diseño interno, los flujos de datos y las garantías de seguridad del núcleo de **OsintUltimate v3.0**, re-arquitecturado íntegramente en Rust para máxima eficiencia y sigilo.

---

## 1. Filosofía de Diseño: "Atomicidad y Concurrencia"

OsintUltimate v3.0 no es solo un escáner; es un **orquestador de inteligencia**. Se basa en tres pilares:
1.  **Costo Cero de Memoria**: Procesamiento de flujos (streaming) mediante `tokio::sync::mpsc` y `JSONL`, permitiendo miles de objetivos en hardware de 1GB RAM.
2.  **Aislamiento de Seguridad**: Cada herramienta externa se ejecuta en un grupo de procesos (`PGID`) propio, con límites de recursos (`rlimit`) y limpieza automática.
3.  **Decisión Autónoma**: Un sistema de IA en cascada (`TieredAIRouter`) elige el mejor modelo (Local, Flash, Pro) según la criticidad del hallazgo.

---

## 2. El Pipeline Circular de 4 Fases

A diferencia de los escáneres lineales, OsintUltimate utiliza un pipeline circular que expande dinámicamente la superficie de ataque.

```mermaid
graph TD
    A[CLI/TUI Input] --> B(Capability Layer Policy)
    B --> C(Approval Gate Check)
    C --> D{Orchestrator}
    D --> E[Fase 1: Descubrimiento OSINT]
    E -- Nuevos Subdominios --> D
    D --> F[Fase 2: Liveness & SSRF Protection]
    F --> G[Fase 3: Escaneo Activo & Explotación]
    G --> H[Fase 4: Data Sink & AI Analysis]
    H -- Acciones Sugeridas --> D
    H --> I[JSONL / HTML Report]
```

### Fase 1: Descubrimiento (Expansion)
*   **Plugins**: `OsintScanner`, `Subfinder`, `Amass`.
*   **Deduplicación**: Implementada mediante `Bloom Filters` y `DashSet` globales para evitar ciclos infinitos.
*   **Velocidad**: Resolución DNS asíncrona nativa (`hickory-resolver`) capaz de 10k+ QPS.

### Fase 2: Liveness & Seguridad
*   **SSRF Shield**: Bloqueo estricto de IPs privadas (`RFC1918`), `CGNAT`, `169.254.x.x` y metadatos cloud.
*   **Verificación Híbrida**: Ping ICMP + TCP Syn + DNS Over HTTPS (DoH) para validar hosts sin dejar rastro en logs de red local.

### Fase 3: Escaneo y Explotación (Capability Layers)
El sistema organiza los plugins en capas de riesgo:
1.  **Passive**: Solo fuentes externas.
2.  **Discovery**: Enumeración ligera.
3.  **Scanning**: Análisis de vulnerabilidades.
4.  **Verification**: Confirmación de hallazgos (Burp/Zap).
5.  **Exploitation**: Ejecución de exploits (SqlMap/Commix).
6.  **Post-Exploitation**: Movimiento lateral y persistencia.

### Fase 4: Data Sink & AI Cascade
*   **Streaming Persistence**: Los resultados se escriben línea a línea en disco como `JSONL`, evitando picos de RAM.
*   **Análisis Tiered**:
    *   **Local (Ollama)**: Análisis rápido de hallazgos informativos.
    *   **Mid (Azure Flash)**: Triaje de vulnerabilidades medianas.
    *   **Premium (Gemini Pro)**: Análisis profundo de cadenas de ataque críticas.

---

## 3. Componentes del Núcleo

### `Orchestrator`
Gestiona la concurrencia a través de `Semaphores` y `RwLock`. Utiliza `StreamExt::buffer_unordered` para maximizar el rendimiento de la red sin saturar la CPU.

### `TieredAIRouter`
Implementa una caché táctica supervisada (`moka`) que evita el consumo excesivo de tokens de IA al recordar análisis de hallazgos similares. Comprime el contexto eliminando headers ruidosos y truncando cuerpos HTTP antes del envío al LLM.

### `ExternalToolGuard`
Envuelve herramientas como `nmap` o `sqlmap`. 
- **Sandboxing**: Limpia variables de entorno y utiliza `setsid`.
- **Resource Control**: Limita la RAM vurtual a 512MB por subproceso.
- **Zombie Prevention**: Mata el `PGID` completo si hay un timeout.

### `MemoryMonitor`
Hilo de fondo que vigila `/proc/self/status`. Implementa **Backpressure**: si el consumo de RAM supera el límite suave, el orquestador pausa la ingesta de nuevos objetivos hasta que la memoria se libere.

---

## 4. Evasión y Sigilo (OPSEC)

1.  **Jitter LogNormal**: En lugar de pausas constantes, utiliza una distribución matemática que imita el comportamiento humano.
2.  **Rotación de Proxies**: Pool de clientes `DashMap` que garantiza una rotación de IP efectiva por cada plugin.
3.  **UA Randomization**: Rotación de User-Agents de navegadores modernos y reales.
4.  **Behavioral Jitter**: Pequeñas variaciones en el orden de los escaneos y tiempos entre peticiones.

---

## 5. Salidas y Reportes

*   **JSONL**: Formato base para procesamiento masivo y estabilidad.
*   **HTML Visual**: Reporte tipo semáforo con tablas interactivas y clasificación CVSS.
*   **Audit Log**: Registro inmutable de cada acción, quién la aprobó y por qué (esencial para cumplimiento normativo).

---

© 2026 RedTeam Lab | OsintUltimate v3.0 Documentation
