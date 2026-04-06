# 🏗️ Arquitectura Técnica OsintUltimate v4.0

> **Motor de Evaluación de Red Team de Alto Rendimiento, Asíncrono y Autónomo**

Este documento detalla el diseño interno, los flujos de datos y las garantías de seguridad del núcleo de **OsintUltimate v4.0**, re-arquitecturado íntegramente en Rust para máxima eficiencia, sigilo y adaptabilidad.

---

## 1. Filosofía de Diseño: "Atomicidad y Concurrencia"

OsintUltimate v3.0 no es solo un escáner; es un **orquestador de inteligencia**. Se basa en tres pilares:
1.  **Costo Cero de Memoria**: Procesamiento de flujos (streaming) mediante `tokio::sync::mpsc` y `JSONL`, permitiendo miles de objetivos en hardware de 1GB RAM gracias al sistema de **Backpressure**.
2.  **Aislamiento de Seguridad Híbrido**: El sistema evalúa el hardware disponible (`Hardware Tiering`) para decidir entre el aislamiento total por **Docker** (para sistemas >= 16GB) o aislamiento nativo por **PGID** (para sistemas <= 8GB), garantizando fluidez sin sacrificar seguridad.
3.  **Decisión Autónoma y Estocástica**: Un sistema de IA en cascada (`TieredAIRouter`) y un motor de evasión probabilístico (`StochasticEvasionPolicy`) eligen la mejor ruta de ataque.

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
    D -- Telemetría SSE --> J[Fase 5: Web Dashboard]
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
    *   **Local (Ollama)**: Análisis rápido de hallazgos informativos y mutación de payloads para evasión de WAF (Thompson Sampling).
    *   **Mid (Azure OpenAI)**: Triaje de vulnerabilidades medianas y correlación de ataques.
    *   **Premium (Gemini Pro)**: Análisis profundo de cadenas de ataque críticas y generación de reportes ejecutivos.

### Fase 5: Command Center Dashboard v2.0 [OPTIMIZADO]
Un servidor embebido **Axum** gestiona una interfaz táctica de alto rendimiento:
*   **SSE (Server-Sent Events)**: Enrutamiento en tiempo real de hallazgos, latidos de sistema y solicitudes de aprobación.
*   **Attack Correlation Graph (D3.js)**: Visualización interactiva de la superficie de ataque y relaciones entre vulnerabilidades mediante grafos de fuerza.
*   **Swarm Monitoring**: Panel de control para supervisar el estado y consumo de tokens de los agentes autónomos (Planner/Scout/Exploiter/Reporter).
*   **Interactive Approval Gate**: Interfaz de decisión para autorizar o abortar acciones de alto riesgo detectadas por el motor.
*   **Zero Footprint**: Todos los assets (HTML/CSS/JS) están embebidos en el binario mediante `rust-embed`.

### Fase de Infraestructura: Adaptabilidad Automática [NUEVO]
El sistema detecta el entorno de ejecución antes de iniciar (`detect_infrastructure`):
- **UltraLowMemory (≤1.5GB RAM)**: Capa la concurrencia a 10 y activa límites estrictos.
- **LocalPC**: Optimiza para 30 hilos y sigilo balanceado.
- **Server**: Desbloquea escalabilidad masiva (100+ hilos).

---

## 3. Componentes del Núcleo

### `Orchestrator`
Gestiona la concurrencia a través de `Semaphores` y `RwLock`. Ahora es **Adaptativo**: ajusta su semáforo de memoria y número de hilos según el hardware detectado en el inicio. Utiliza `StreamExt::buffer_unordered` para maximizar el rendimiento.

### `TacticalWebhookSink` [OPTIMIZADO]
Diseñado para entornos de alta latencia (C2 remoto/VPS):
- **Batching**: Acumula hasta 10 objetivos/hallazgos antes de realizar el envío.
- **Compresión Gzip**: Comprime los payloads de red mediante `flate2` para minimizar el tráfico y la latencia.

### `SandboxDispatcher` (Inspirado en ExternalToolGuard)
Es el componente encargado de la ejecución de binarios externos.
- **Hardware Tiering**: Selecciona entre `Docker` o `Nativo` según la RAM.
- **Explotación Segura**: Fuerza Docker para herramientas de explotación, incluso en entornos de bajos recursos.
- **Resource Control**: Consulta al `SysResourceManager` para evitar colapsar la RAM del host.
- **Zombie Prevention**: Mata el `PGID` completo si hay un timeout en modo nativo.

### `SourceAnalyzer` [NUEVO Vector 7]
El componente encargado de la integración del código fuente en el ciclo de vida del escaneo.
- **Git Connector**: Permite clonar repositorios efímeramente para análisis dinámico.
- **Extractor de SAST Ligero**: Motor de detección de patrones orientado a endpoints y sinks peligrosos en JS/TS y Python.
- **SAST-DAST Linker**: Colabora con el `CorrelationEngine` para elevar la confianza de hallazgos dinámicos basados en la lógica del código fuente.
- **Minificador de Código**: Pre-procesa snippets para reducir el consumo de tokens en la IA antes del envío.

### `DecoyController` [NUEVO]
Gestiona el ciclo de vida de señuelos DNS (via Cloudflare) y tripwires persistentes (via SQLite WAL).

### `WafEvasionEngine` [NUEVO]
Máquina de estados reactiva que escala de Headers → TLS → Local AI → IP Rotation ante respuestas HTTP 403.

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
*   **SQLite**: Persistencia relacional para consultas complejas y gestión de estado.
*   **Lock-Free Sink**: Uso de `SegQueue` para inserciones masivas sin bloqueos de Mutex en la base de datos.
*   **HTML Visual**: Reporte tipo semáforo con tablas interactivas y clasificación CVSS.
*   **Audit Log**: Registro inmutable de cada acción, quién la aprobó y por qué.

---

© 2026 RedTeam Lab | OsintUltimate v4.0 Documentation
