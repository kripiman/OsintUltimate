# 🛡️ Hardening y SIGILO (OPSEC)

Este documento describe las medidas de seguridad interna y tácticas de evasión implementadas en OsintUltimate v3.0 para garantizar la **estabilidad del sistema** y la **invisibilidad operativa**.

---

## 1. Protección de Recursos (Hardening de Memoria)

Optimizado para entornos con **1GB de RAM** (ej. AWS t3.micro, Azure B1s, GCP f1-micro).

### Vigilancia de Memoria (`MemoryMonitor`)
- **Límite Suave (600MB)**: Activa el `Backpressure`. El orquestador pausa la lectura de nuevos objetivos.
- **Límite Duro (900MB)**: Provoca un apagado de emergencia (`Greaceful Shutdown`) para proteger al sistema operativo de un OOM (Out Of Memory) fatal.
- **Logging**: El monitor registra el uso de RAM actual y el pico (`VmRSS`) cada 500ms en `/proc/self/status`.

### Límites de Subprocesos (`rlimit`)
OsintUltimate encapsula cada herramienta externa (Nmap, Nuclei, SqlMap) con restricciones estrictas de recursos:
- **`libc::setrlimit(RLIMIT_AS, 512MB)`**: Ninguna herramienta individual puede consumir más de 512MB de memoria virtual.
- **`libc::setsid()`**: Cada herramienta vive en su propia sesión de proceso aislada, evitando que señales accidentales (como un Ctrl+C mal capturado) afecten al motor principal.

---

## 2. Evasión Avanzada (Sigilo)

OsintUltimate v3.0 implementa tácticas de evasión de grado militar para eludir WAFs (Web Application Firewalls) y EDRs (Endpoint Detection and Response).

### `HumanJitter` (LogNormal)
Evitamos los "patrones de claqueo" (click patterns) predecibles. En lugar de una espera lineal de 2 segundos, utilizamos una **distribución LogNormal** con una media de ~7.4 segundos pero con una "cola larga" que puede llegar a 30 segundos. Esto simula de forma matemática el comportamiento de navegación humana errática.

### Rotación de Identidad (`ProxyManager`)
- **Huella de Red Dinámica**: Cada petición HTTP puede usar un proxy distinto si se proporciona una lista de proxies (`--proxies`).
- **User-Agent Realista**: Rotación de una lista curada de User-Agents correspondientes a las versiones más recientes de Chrome y Firefox en Windows, Mac y Linux.
- **Identity Bonding**: El sistema mantiene una correlación entre el User-Agent y el Proxy para una sesión dada, evitando inconsistencias que alertan a los sistemas anti-bot.

### DNS sobre HTTPS (DoH)
Las consultas DNS tradicionales a menudo son el primer punto de detección por parte de los Blue Teams (SOC/SIEM). OsintUltimate permite el uso de **DoH (DNS over HTTPS)** vía Cloudflare o Google, cifrando nuestras consultas de resolución de objetivos y haciéndolas indistinguibles del tráfico HTTPS normal.

---

## 3. Prevención de Riesgos (Sandboxing)

### `ExternalToolGuard` (Prevención de Zombis)
Los plugins que ejecutan binarios externos son gestionados por un guardián de procesos:
1.  **Timeout Táctico**: Si una herramienta tarda más de lo esperado (ej. 300s para Nmap), el guardián actúa.
2.  **PGID Kill**: En lugar de matar solo el proceso padre (nmap), enviamos una señal de muerte al **ID del Grupo de Procesos (PGID)** negativo. Esto garantiza que cualquier proceso hijo "huérfano" también sea eliminado de la memoria.
3.  **Limpieza de Entorno**: Eliminamos todas las variables de entorno (`env_clear`) del sistema padre antes de ejecutar la herramienta, evitando fugas de información o interferencias de configuración.

---

## 4. Protección SSRF (Server-Side Request Forgery)

El núcleo implementa una validación asíncrona de liveness que protege al Red Team de escanear accidentalmente infraestructura interna del objetivo:
- **Bloqueo `RFC1918`**: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16.
- **Bloqueo `CGNAT` / Cloud Metadata**: 100.64.0.0/10 y 169.254.169.254.
- **Bloqueo `IPv6`**: Rangos de documentación y metadatos IPv6.

---

© 2026 RedTeam Lab | OsintUltimate v3.0 Documentation
