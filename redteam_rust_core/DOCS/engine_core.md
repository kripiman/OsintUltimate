# ⚙️ Engine Core: El Pipeline Soberano (v0.1.0)

El núcleo de OsintUltimate está diseñado para el alto rendimiento y la ejecución autónoma en entornos endurecidos. El sistema se coordina mediante canales asíncronos y memoria protegida para garantizar la soberanía de los datos.

## 1. El Pipeline Soberano (Arquitectura de 4 Etapas)

La arquitectura de datos de OsintUltimate garantiza que cada activo pase por una serie de guardias de seguridad y enriquecimiento antes de su persistencia final.

### Diagrama de Flujo del Pipeline
```mermaid
graph LR
    E0[Stage 0: Prep] --> E1[Stage 1: Liveness]
    E1 --> E2[Stage 2: Tactical & Discovery]
    E2 --> E3[Stage 3: Sovereign Persistence]
    
    E2 -.->|Recursion| E1
```

---

## 2. Inmersión Técnica por Etapa

### Etapa 0: Mission Preparation & Ingestion
Antes de iniciar cualquier acción de red, el sistema inicializa el entorno operativo:
- **Metadatos**: Se genera un objeto `ScanMetadata` que firma la línea de comandos utilizada y el timestamp de inicio.
- **Backpressure**: Escala el tamaño de los canales `mpsc` según la concurrencia configurada.
- **Sink Init**: Los sumideros abren los manejadores de archivos en modo exclusivo.

### Etapa 1: Liveness Verification (Gate)
La barrera de seguridad crítica del sistema que valida cada objetivo antes del asalto:
- **Egress Shielding**: La función `is_safe_ip` valida cada resolución DNS.
- **Protección DNS Rebinding**: Bloquea IPs privadas (RFC1918) y loopback, forzando la resolución a IPs estables (`resolved_ip`) para mitigar ataques de rebinding durante la ejecución.

### Etapa 2: Tactical Execution & Discovery (War Room)
El motor de asalto donde reside la inteligencia y se expande la superficie:
- **Orquestador**: Gestiona la ejecución concurrente de plugins mediante `JoinSet`.
- **Recursión Táctica**: Los activos descubiertos se re-inyectan en la Etapa 1 para una exploración profunda.
- **Memory Backpressure**: Un semáforo monitoriza el uso de memoria; si se detecta presión crítica, se pausa el despacho de nuevos agentes.
- **Enriquecimiento (Intel)**: Los hallazgos se mapean automáticamente a CVEs mediante un `CveCacheManager` global.
- **Correlación de Cadenas de Ataque**: Un motor de grafos tácticos vincula hallazgos aislados (ej. filtración de JS -> bypass 403) para generar reportes consolidados de alto impacto.

### Etapa 3: Sovereign Persistence (Out)
Persistencia de alta velocidad basada en **Lock-Free Concurrency**:
- **MultiSink**: Distribuye los resultados a PostgreSQL, JSONL y Webhooks tácticos de forma asíncrona.
- **Graceful Shutdown**: El sistema utiliza `CancellationToken` para garantizar que todos los buffers se vacíen a disco antes de finalizar el proceso, incluso tras una interrupción.

---

## 3. Seguridad de Plugins y Aislamiento

OsintUltimate implementa una cadena de carga de plugins endurecida para garantizar la integridad binaria:
1.  **Harden Path**: Normalización de rutas de plugins.
2.  **Atomic File Lock**: Bloqueo exclusivo del archivo durante la verificación.
3.  **FD-based Signature Verification**: La firma Ed25519 se verifica directamente desde el File Descriptor bloqueado para mitigar ataques **TOCTOU**.
4.  **ABI Check**: Verificación de compatibilidad binaria estricta.
5.  **Capability Gate**: Validación de permisos requeridos por el plugin.
6.  **Sandbox Isolation**: Ejecución en entornos Docker aislados con enrutamiento proxy forzado.
7.  **Policy Alignment**: Validación contra `ScanLayerPolicy`.

---

> [!IMPORTANT]
> El pipeline está diseñado para ser **Fail-Closed**. Si la comprobación de salud de la Etapa 3 falla para un host, el sistema descarta el objetivo por completo en lugar de arriesgar una ejecución sin proxies o con IPs inseguras.
