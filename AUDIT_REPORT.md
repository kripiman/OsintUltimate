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

- [**MITIGADA**] **Bypass de Whitelist**: `nc`, `python3` y `netcat` permanecen fuera de la whitelist de comandos permitidos. 
  - *Evidencia*: `core/poc_validator.rs:138` (Lista estricta: `nmap`, `curl`, `ping`, `whois`, `dig`, `host`).
- [**MITIGADA**] **SSRF Core Validation**: El motor de liveness ha sido expandido para bloquear rangos críticos (CGNAT, Documentation, Multicast).
  - *Evidencia*: `utils/liveness.rs:14-71` (Hardening de `is_safe_ip`).
- [**MITIGADA**] **Data Races en FFI**: Se utiliza un `Mutex<()>` global para serializar el acceso a plugins dinámicos.
  - *Evidencia*: `plugins/ffi.rs:51, 111` (Uso de `sync_lock`).

---

## 3. HALLAZGOS ACTIVOS (Nivel Enterprise)

### 3.1 [CRIT-001] — Argument Injection en Validación de PoC
- **Archivo**: `core/poc_validator.rs` (Líneas 145-162)
- **Severidad**: 🔴 **CRÍTICO**
- **Descripción**: Se ha implementado una validación semántica basada en **blacklist** (`forbidden_flags`). Aunque bloquea ataques obvios (`-o`, `--exec`), este enfoque es reactivo y permite bypasses mediante argumentos menos comunes o alias de herramientas (ej. `curl -K` para leer archivos locales).
- **Evidencia Técnica**:
    ```rust
    // poc_validator.rs:147
    let forbidden_flags = ["-o", "--output", "-f", "--file", "--script", "--exec", ...];
    for arg in &args[1..] {
        if forbidden_flags.iter().any(|&f| lower_arg.starts_with(f)) { 
            anyhow::bail!("Dangerous argument..."); 
        }
    }
    ```
- **Riesgo**: Persistencia de RCE limitado o exfiltración de archivos mediante herramientas autorizadas ("Living off the land").

### 3.2 [HIGH-001] — DNS Rebinding Parcial (TOCTOU en Herramientas Externas)
- **Archivo**: `core/poc_validator.rs` (Líneas 164-173 y 221-255)
- **Severidad**: 🟠 **ALTO**
- **Descripción**: V12 introduce **IP Pinning** (sustitución manual de hostnames por IPs resueltas). Sin embargo, herramientas como `curl` o `nmap` pueden realizar resoluciones internas adicionales (ej. seguimiento de redirecciones o escaneos recursivos) si el pinning no se propaga a todas las sub-llamadas.
- **Evidencia Técnica**: El pinning solo ocurre en el array de argumentos inicial, no en la configuración interna de la herramienta ni en la lógica de resolución recurrente del sistema operativo.

### 3.3 [HIGH-002] — Swarm Resource Exhaustion (DoS de Memoria/Tokens)
- **Archivo**: `core/swarm.rs` (Líneas 42, 169)
- **Severidad**: 🟠 **ALTO**
- **Descripción**: 
    1. Si `max_tokens` se configura como `0`, el sistema opera sin presupuesto, permitiendo un consumo infinito de fondos de la API ante un bucle infinito de la IA.
    2. La reserva de 1000 tokens por agente es estática y no escala con la complejidad de la tarea.
    3. No existe un límite estricto de hilos concurrentes en el `JoinSet` del Swarm, lo que podría llevar a un agotamiento de descriptores de archivos o memoria.

### 3.4 [MED-001] — Escape de Aislamiento FFI (SIGSEGV/SIGKILL)
- **Archivo**: `plugins/ffi.rs` (Línea 118)
- **Severidad**: 🟡 **MEDIO**
- **Descripción**: `catch_unwind` solo captura pánicos de Rust. Un error de memoria (C-style) o un SIGSEGV en una librería externa cargada vía FFI terminará inmediatamente el proceso de `OsintUltimate` sin posibilidad de recuperación.

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
| CRIT-001 | 🔴 | Argument Injection (Blacklist) | **ACTIVO** | `poc_validator.rs:147` |
| HIGH-001 | 🟠 | DNS Rebinding (TOCTOU) | **ACTIVO** | `poc_validator.rs:164` |
| HIGH-002 | 🟠 | Swarm Resource DoS | **NUEVO** | `swarm.rs:42` |
| HIGH-003 | 🟠 | Leak de IP en Nube (Oracle TOS) | **DISEÑO** | `pipeline.rs:174` |
| MED-001 | 🟡 | Escape de Aislamiento FFI | **NUEVO** | `ffi.rs:118` |

---

> **Veredicto Final**: El sistema ha mejorado significativamente mediante la implementación de IP Pinning y validación semántica inicial. Sin embargo, persisten riesgos críticos derivados de la confianza en las entradas de la IA (Argument Injection) y la falta de aislamiento físico de los plugins FFI. **Se recomienda la migración inmediata a un modelo de validación basado en Templates (P0).**
