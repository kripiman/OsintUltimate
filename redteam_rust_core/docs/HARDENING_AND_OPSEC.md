# 🛡️ Hardening Stealth y SIGILO (Protocolo V13)

Este documento describe la arquitectura de endurecimiento y las tácticas de evasión de grado militar integradas en **OsintUltimate V13**. El objetivo es garantizar la invisibilidad operativa y la integridad del sistema ante contramedidas avanzadas de WAF, EDR y equipos de Blue Team.

---

## 1. Protección de Egress y Evasión de RED

### Detección de Infraestructura OCI (P0)
Si el motor detecta que se está ejecutando dentro de Oracle Cloud Infrastructure (`stealth_detect.rs`), activa automáticamente el **aislamiento de salida total**. Todas las conexiones ofensivas se enrutan imperativamente a través de la infraestructura efímera para evitar que el objetivo identifique la IP de origen del orquestador.

### Aprovisionamiento Autónomo de Proxies (DigitalOcean)
- **Despliegue Just-in-Time**: Se lanzan nodos de salida en regiones aleatorias de DigitalOcean ante detecciones de bloqueo (403/WAF).
- **Auto-Destrucción Táctica**: Los nodos tienen un script de limpieza que los apaga tras 4 horas para eliminar rastros forenses y controlar costos.
- **Enrutamiento por Proxy-Wrapping**: Las herramientas externas (nmap, curl, sqlmap) son invocadas mediante envoltorios que inyectan configuraciones de proxy SOCKS5 dinámicamente.

---

## 2. Hardening del Validador de PoC (`PocValidator`)

El sistema de validación de Proof-of-Concept ha sido rediseñado para evitar inyecciones y fugas:

1.  **Validación Semántica de Argumentos**: No se permiten argumentos de línea de comandos arbitrarios. Las herramientas se ejecutan bajo plantillas que validan cada flag contra una lista blanca (Whitelist).
2.  **Pinning de IP de Destino**: Previene el **DNS Rebinding**. Una vez resuelto el dominio, la IP se fija internamente para todas las fases de escaneo y explotación.
3.  **SSRF Shield Multinivel**: Bloqueo asíncrono de rangos de red internos, metadatos cloud (169.254.169.254) y direcciones no enrutables antes de iniciar cualquier conexión.

---

## 3. Sigilo de Comportamiento (Behavioral OPSEC)

- **Jitter Log-Normal**: Los retrasos entre peticiones no son constantes; siguen una distribución matemática que imita la interacción humana.
- **RT-Identity (Fingerprinting Consistent)**: El sistema vincula un `User-Agent` específico y una versión de `TLS` a cada IP de salida para mantener la coherencia de identidad durante toda la sesión contra un objetivo.
- **Thompson Sampling**: El motor de evasión elige dinámicamente la mejor técnica de salto de WAF basándose en el éxito de ejecuciones previas.

---

## 4. Gestión Adaptativa de Recursos

V13 implementa **Backpressure Autoconsciente**:
- **Monitorización de RAM**: El hilo `MemoryMonitor` vigila el consumo del proceso.
- **Límites Dinámicos**: Si el sistema detecta solo 1GB de RAM, se reduce la concurrencia a 5-10 hilos y se desactiva el sandboxing pesado (Docker) en favor de `ProcessGuard` nativo.
- **Aislamiento `rlimit`**: Cada subproceso se lanza con límites de memoria virtual (`RLIMIT_AS`) de 512MB para evitar ataques de agotamiento de recursos por parte del objetivo.

---

## 5. Salidas y Auditoría Inmutable

- **Lock-Free Sink**: Los hallazgos se escriben de forma no bloqueante utilizando `SegQueue`, evitando lags en el motor de escaneo.
- **Audit Log**: Cada acción de alto riesgo (ej. ejecución de exploit) requiere aprobación manual vía **Approval Gate** y queda registrada con la identidad del operador y la justificación táctica.

---

© 2026 RedTeam Lab | OsintUltimate V13 Hardening Protocol
