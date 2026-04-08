# Auditoría de Seguridad — Caja Blanca (V12)
# Proyecto: OsintUltimate / `redteam_rust_core`

> **Fecha**: 2026-04-07 (V12 — White-Box Final Status)
> **Auditor**: Senior Security Researcher & Rust Systems Auditor
> **Estado**: CRÍTICO (Debido a fallos en validación semántica y riesgos de infraestructura)

---

## 1. RESUMEN EJECUTIVO (Enterprise Overview)

Esta versión V12 del reporte de auditoría concluye la revisión técnica profunda del núcleo en Rust. Tras aplicar una metodología de **Zero-Trust Documentation**, se han identificado discrepancias críticas entre las mitigaciones afirmadas y la implementación real. 

Aunque el endurecimiento de la fase V11 persiste (eliminación de binarios peligrosos), la introducción de sistemas complejos como el `Swarm` y el bridge `FFI` han abierto nuevos vectores de ataque. El sistema ha evolucionado de tener vulnerabilidades triviales a poseer debilidades arquitectónicas sutiles pero de alto impacto, especialmente en el contexto de despliegue en infraestructuras de nube de terceros (Oracle/DigitalOcean).

---

## 2. VERIFICACIÓN DE MITIGACIONES (Regresiones y Persistencia)

Se confirma la persistencia de las protecciones de nivel básico, descartando regresiones en los siguientes puntos:

- [**MITIGADA**] **Bypass de Whitelist**: `nc`, `python3` y `netcat` permanecen fuera de la lista de binarios permitidos. El motor de `safe_command` reconstruye comandos a partir de plantillas fijas.
  - *Evidencia*: `core/poc_validator.rs:147-169` (Rechazo de binarios no permitidos y plantillas estrictas de argumentos).
- [**MITIGADA**] **SSRF Core Validation**: La lógica de liveness bloquea rangos críticos y el pipeline fija `resolved_ip` tras la verificación de conectividad.
  - *Evidencia*: `utils/liveness.rs:14-71` (Hardening de `is_safe_ip`) y `core/pipeline.rs:144-147` (Pin IP antes de escaneo).
- [**MITIGADA**] **Data Races en FFI**: Se utiliza un `Mutex<()>` para serializar cada ejecución de plugin FFI y evitar accesos concurrentes al bridge.
  - *Evidencia*: `plugins/ffi.rs:51, 111-121` (Uso de `sync_lock` y `catch_unwind`).

---

## 3. HALLAZGOS ACTIVOS (Nivel Enterprise)

### 3.1 [CRIT-001] — SSRF por Redirección en `execute_http`
- **Archivo**: `core/poc_validator.rs` (Líneas 231-267)
- **Severidad**: 🔴 **CRÍTICO**
- **Descripción**: `execute_http` fija el IP resuelto y valida el rango contra SSRF, pero construye un `reqwest::Client` sin política de redirección explícita. La solicitud inicial usa la IP fijada, pero una cabecera `Location` maliciosa podría desencadenar una redirección hacia un host externo seguro, invalidando el pinning.
- **Evidencia Técnica**:
    - `reqwest::Client::builder().timeout(...).danger_accept_invalid_certs(true).build()?` en `core/poc_validator.rs:232-235`
    - `request.send().await?` en `core/poc_validator.rs:263`
- **Riesgo**: SSRF/Exfiltración a través del seguimiento automático de redirecciones.

### 3.2 [HIGH-001] — Swarm Task Queue Growth / Agotamiento de Recursos
- **Archivo**: `core/swarm.rs` (Líneas 148-197)
- **Severidad**: 🟠 **ALTO**
- **Descripción**: Aunque el Swarm limita la concurrencia a 10 agentes activos, el `JoinSet` no está acotado y puede acumular una gran cantidad de tareas si `discovery_rx` produce muchos hallazgos. Esto crea un vector DoS de memoria/descriptores y mantiene reservas de tokens durante el tiempo de vida de cada tarea.
- **Evidencia Técnica**:
    - `let mut join_set = tokio::task::JoinSet::new();` en `core/swarm.rs:148`
    - `join_set.spawn(...)` en `core/swarm.rs:181-196`
    - `let agent_semaphore = Arc::new(tokio::sync::Semaphore::new(10));` en `core/swarm.rs:150`
- **Nota**: `TokenBudget::new(0)` ya mitiga el bypass de presupuesto cero, pero no elimina el riesgo de acumulación de tareas.

### 3.3 [MED-001] — Escape de Aislamiento FFI (SIGSEGV/SIGKILL)
- **Archivo**: `plugins/ffi.rs` (Líneas 119-121)
- **Severidad**: 🟡 **MEDIO**
- **Descripción**: `catch_unwind` solo atrapa pánicos de Rust. Un fallo de memoria nativo en un plugin cargado vía FFI seguirá propagándose como SIGSEGV/SIGKILL y matará el proceso anfitrión.
- **Evidencia Técnica**:
    - `let result = catch_unwind(AssertUnwindSafe(move || { unsafe { (ffi.scan)(plugin_ptr, target_ptr) } }));` en `plugins/ffi.rs:119-122`
- **Riesgo**: Crash del orquestador por plugins inseguros.

---

## 4. RECOMENDACIONES TÉCNICAS (V12 Roadmap)

### P0: Hardening Proactivo de PoC (Templates)
- **Acción**: Eliminar la validación por blacklist de argumentos.
- **Implementación**: Migrar a un sistema de plantillas estricto. La IA solo debe proporcionar valores (ej. `PORT`, `PATH`) que se inyectan en una cadena de comando pre-aprobada:
  - *Correcto*: `format!("nmap -p {} -sV {}", port, ip)`
  - *Incorrecto*: `cmd.args(&args[1..])`

### P1: Aislamiento de Ejecución (Master-Worker)
- **Acción**: Separar el Orquestador (Oracle Cloud) de los Ejecutores (DigitalOcean).
- **Implementación**: Usar un bridge mTLS/Wireguard. El Orquestador envía la intención, el Ejecutor en DO valida la IP, clava la IP a nivel de socket y ejecuta la herramienta.

### P2: Sandbox Nativo de Plugins
- **Acción**: Envolver las llamadas FFI en procesos hijos aislados o usar WebAssembly (Wasmtime) para plugins. Esto garantiza que un SIGSEGV en un plugin no mate al orquestador.

---

## 5. TABLA RESUMEN V12

| ID | Severidad | Hallazgo | Estado | Evidencia (Línea) |
|----|-----------|----------|--------|-------------------|
| CRIT-001 | 🔴 | SSRF por redirección en `execute_http` | **ACTIVO** | `core/poc_validator.rs:232-267` |
| HIGH-001 | 🟠 | Swarm Task Queue Growth / DoS | **ACTIVO** | `core/swarm.rs:148-197` |
| MED-001 | 🟡 | Escape de Aislamiento FFI | **NUEVO** | `plugins/ffi.rs:119-123` |

---

> **Veredicto Final**: El sistema muestra mejoras importantes en el control de binarios y en la fijación de IPs, pero la protección SSRF no está completa en `execute_http` y la arquitectura del Swarm aún presenta un vector de agotamiento de recursos. La prioridad inmediata debe ser cerrar el SSRF por redirección y aplicar límites de retención/tamaño al `JoinSet` de agentes.
