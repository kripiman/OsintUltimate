# Casos de Uso y Combinaciones (Playbooks)

A nivel arquitectónico, la ventaja de utilizar OsintUltimate es que permite modelar múltiples Vectores y Escenarios de Operación según el grado de "ruido" aceptable. A continuación se presentan las combinaciones profesionales más eficientes (que ahora están embebidas lógicamente en el TUI/Menú Interactivo).

## 1. Perfil A: Discovery "Zero Noise" 
**Propósito**: Obtener el footprinting completo de la organización sin enviar un solo paquete a la infraestructura objetivo.

*   **Flags Recomendados**: Ninguno predeterminado soporta el modo puro-off aún desde CLI, pero el uso estructural requiere resolver DoH de dominios externos.
*   **Estrategia**: Depende 100% de `OsintScanner` y resuelve pasivamente todo vía Cloudflare DoH o Google DoH.

## 2. Perfil B: Stealth Audit ("Low & Slow")
**Propósito**: Realizar un escaneo a través del fuego cruzado de WAFs avanzados como Cloudflare o Akamai sin emitir alertas SOC. El escaneo dura más pero no levanta bloqueos temporales.

*   `--stealth`: Aplica distribución Log-Normal (`HumanJitter`)
*   `--scan-type sS`: Escaneo SYN, no establece un hand-shake 3-way en los sockets del destino.
*   `--fragment`: Cruza inspecciones SPI rudimentarias.
*   `--concurrency 5`: Disminuye deliberadamente el "fan-out" para mantener los Request/Second bajos en total.
*   `--proxies "socks5://10.x...,http://8.x..."`: Salta de IP para despistar el token tracking.
*   `--doh`: Encripta telemetría DNS.
*   **CLI**: `./redteam_rust_core -t mercadolibre.com --stealth --concurrency 5 --doh --scan-type "sS" --fragment`

## 3. Perfil C: Aggressive Full Surface Enumeration
**Propósito**: Usualmente tras horas de oficina o en White-Box Pentesting. Obtener la mayor cantidad de información y explotaciones automáticas asumiendo que el cliente aprobó el ruido.

*   `--scripts "default,vuln,exploit"`: Dispara todos los Nmap Scripting Engines en un pool distribuido.
*   `--service-detection`: Cifra las cabeceras exactas (ej. IIS 10.0 vs 8.5) al precio de múltiples round-trips de sondeo (-sV).
*   `--concurrency 500`: Agota literalmente los sockets disponibles pero acorta el tiempo horas -> minutos en redes internas 10GbE.
*   **CLI**: `./redteam_rust_core -t internal.network.local --concurrency 500 --service-detection --scripts "vuln,auth"`

---

## Panel de Reportes

Una vez generados los payloads, toda combinación concluye en `scan_report.html`. Un aspecto crítico de la seguridad OPSEC es nunca subir el output JSON directamente a motores públicos; este framework compila el HTML Off-line incrustado, previniendo fuga de los findings vía telemetría externa.
