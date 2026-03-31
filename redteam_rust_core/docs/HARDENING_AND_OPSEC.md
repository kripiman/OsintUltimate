# 🛡️ Hardening y SIGILO (OPSEC)

Este documento describe las medidas de seguridad interna y tácticas de evasión implementadas en OsintUltimate v4.0 para garantizar la **estabilidad del sistema** y la **invisibilidad operativa**.

---

## 1. Protección de Recursos (Hardening de Memoria)

Optimizado para entornos con **1GB de RAM** (ej. AWS t3.micro, Azure B1s, GCP f1-micro).

### Vigilancia de Memoria Adaptativa y Backpressure
Optimizado dinámicamente según el hardware detectado:
- **UltraLowMemory Mode (Adaptativo)**:
  - **Límite Suave (500MB)**: Activa el `Backpressure`. El orquestador pausa la lectura de nuevos objetivos.
  - **Límite Duro (850MB)**: Provoca un apagado de emergencia (`Graceful Shutdown`) protegiendo al sistema operativo.
  - **Concurrencia**: Capada automáticamente a un máximo de 5-10 hilos simultáneos.
- **LocalPC/Server Default**:
  - **Límite Suave (600MB)** / **Límite Duro (900MB)**.
- **Logging**: El monitor registra el uso de RAM actual y el pico (`VmRSS`) en `/proc/self/status`.

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

### Dynamic Infrastructure Stealth [NUEVO]
El flag `--stealth` activa la orquestación de infraestructura efímera:
- **DigitalOcean Nodes**: El sistema utiliza la API de DigitalOcean para crear un droplet en una región aleatoria (ej. `nyc1`, `ams3`).
- **Proxy Iniection**: Una vez activo, el nodo se autodetecta y se inyecta en el `ProxyManager` como el nodo de salida primario.
- **Auto-Destruction**: Al finalizar el escaneo, el motor destruye la infraestructura para eliminar el rastro y minimizar costos.

### 🛡️ Evasión de WAF Adaptativa (Escalación de 4 Etapas)
OsintUltimate v3.1 introduce un motor de evasión inteligente que reacciona automáticamente a bloqueos HTTP 403:
1.  **Rotación de Cabeceras**: Cambia User-Agents y cabeceras de fingerprinting sin coste.
2.  **Mutación de TLS**: Cambia el perfil de negociación TLS (Chrome, Firefox, Safari) para evadir firmas de nivel 4.
3.  **Local AI Payload Rewrite**: Utiliza Ollama (Local) para reescribir payloads sospechosos antes de reintentar (OPSEC estricto).
4.  **Rotación de IP Ephemeral**: Despliega un nuevo nodo en DigitalOcean para obtener una IP limpia y continuar la operación.

---

## 3. Infraestructura Defensiva: Honeypot-Decoy Mapping [NUEVO]

### Hardware-Aware Resource Hardening [OPTIMIZADO]

OsintUltimate v4.0 es ahora **autoconsciente** de su entorno de ejecución:
1.  **Detección de RAM**: El motor clasifica el host (UltraLowMemory, LocalPC, Server).
2.  **Backpressure Dinámico**: Si el `MemoryMonitor` detecta que la RAM libre cae por debajo de los 500MB (soft limit), el orquestador pausa automáticamente el procesamiento de nuevos objetivos.
3.  **Concurrency Capping**: En sistemas de 1GB RAM, el motor limita la concurrencia a 10 hilos para garantizar la estabilidad de la red y evitar el kernel OOM-killer.
- **Atribución**: Captura IPs de origen, User-Agents y hashes JA3 de los atacantes/analistas.

---

## 4. Web Dashboard (Zero Trace) [NUEVO]

El nuevo panel de control ha sido diseñado con el sigilo en mente:
- **Localhost Bound**: Por defecto, el servidor Axum solo escucha en `127.0.0.1`, minimizando la superficie expuesta.
- **SSE Efficiency**: La tecnología **Server-Sent Events** reduce drásticamente las conexiones repetitivas al servidor, haciendo que el tráfico interno sea indistinguible de la actividad normal del kernel.
- **Embedded Assets**: Al no requerir un servidor web externo (Nginx/Apache), no deja rastros en los logs del sistema sobre instalaciones de dependencias web.
- **Local AI Privacy**: Los reintentos de evasión generados vía Ollama se mantienen 100% locales, protegiendo las tácticas de exfiltración de ser analizadas por proveedores cloud.

---

## 4. Prevención de Riesgos (Sandboxing)

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

## 5. Auditoría de Despliegue (DevOps Hardening) [NUEVO]

### Docker de Grado Alpine
Para entornos críticos de baja memoria, la imagen Docker ha sido migrada a **Alpine Linux**:
- **Base Minimalista**: Reduce el consumo de RAM del contenedor base en un 70% comparado con Debian.
- **Static linking (musl)**: El binario se compila estáticamente.

### Advertencia Preventiva de Docker en 1GB
En hardware de **1GB RAM**, OsintUltimate emite una advertencia crítica contra el uso de Docker. Se recomienda la ejecución nativa en estos casos.

---

© 2026 RedTeam Lab | OsintUltimate v4.0 Documentation
