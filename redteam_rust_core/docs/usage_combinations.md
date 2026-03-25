# 🎯 Casos de Uso y Combinaciones (Playbooks) v3.0

OsintUltimate v3.0 permite modelar vectores de ataque específicos ajustando la agresividad, el sigilo y la profundidad del escaneo. Estos "Playbooks" están diseñados para escenarios reales de Red Team.

---

## 🚀 Perfil A: Reconocimiento Pasivo (Zero Noise)
**Propósito**: Obtener el footprinting completo de la organización sin enviar paquetes directos a la infraestructura objetivo.

*   **Flags**: `--max-layer passive --doh`
*   **Estrategia**: Depende 100% de `OsintScanner` y fuentes externas (`crt.sh`, Shodan).
*   **Sigilo**: Máximo. No hay interacción con el objetivo.

## 🕵️ Perfil B: Auditoría Sigilosa (Low & Slow)
**Propósito**: Evadir WAFs avanzados (Cloudflare, Akamai) y no levantar alertas en el SOC.

*   **Flags**: `--stealth --max-layer scanning --concurrency 5 --doh --proxies "http://pool:8080"`
*   **Mecanismos**: 
    - `HumanJitter`: Distribución Log-Normal para imitar clics humanos.
    - `Rotación de Proxies`: Cambia de IP en cada plugin.
    - `UA Rotation`: Cambia el User-Agent por cada petición.
*   **Uso**: `./redteam_rust_core -t objetivo.com --stealth --concurrency 5 --doh`

## 🔥 Perfil C: Enumeración Agresiva de Superficie
**Propósito**: White-Box Pentesting o escaneos internos en redes de alta velocidad (10GbE).

*   **Flags**: `--max-layer verification --concurrency 100 --service-detection --scripts "default,vuln"`
*   **Mecanismos**:
    - `Concurrency 100`: Explota el runtime asíncrono para escanear miles de servicios en minutos.
    - `Service Detection (-sV)`: Identificación precisa de versiones.
*   **Uso**: `./redteam_rust_core -t red.interna.local --concurrency 100 --service-detection --scripts "vuln"`

## 🤖 Perfil D: Agente Autónomo (Sentinel)
**Propósito**: Evaluación autónoma total. La IA decide qué hacer basándose en los hallazgos.

*   **Flags**: `--autonomous --max-layer exploitation --interactive`
*   **Mecanismos**:
    - `TieredAIRouter`: Análisis en cascada (Local -> Mid -> Premium).
    - `Autonomous Execution`: Si la IA detecta una vulnerabilidad, sugiere y ejecuta el siguiente plugin (ej. lanza sqlmap si encuentra un parámetro sospechoso).
    - `Approval Gate`: Solo ejecuta acciones de explotación si el usuario las aprueba interactivamente.
*   **Uso**: `./redteam_rust_core -t objetivo.com --autonomous --max-layer exploitation --interactive`

---

## 📊 Panel de Reportes

Toda ejecución concluye con la generación de `scan_report.html`. 
- **Privacidad**: El reporte se compila **offline**, incrustando todos los datos necesarios para evitar fugas de información a servidores de telemetría externos.
- **Formato**: JSONL (para procesamiento posterior) y HTML (para presentación ejecutiva).

---

© 2026 RedTeam Lab | OsintUltimate v3.0 Documentation
