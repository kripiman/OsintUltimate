# 🖥️ Especificaciones del Sistema y Plan de Optimización (Student v4.x)

Este documento guarda el contexto de hardware de la máquina de desarrollo y el plan táctico para escalar **OsintUltimate** con recursos limitados (**8GB RAM**).

## 🛡️ Especificaciones del Hardware (Auditado)
*   **Procesador:** Intel i3-10100F (4C/8T, 4.3 GHz).
*   **Gráfica:** AMD Radeon RX 580 (2048SP) — *Compatible con ROCm*.
*   **Memoria RAM:** 8GB DDR4 (~7.8GB utilizables).
*   **Almacenamiento SSD:** 215 GB (Sistema Operativo Debian Server).
*   **Almacenamiento HDD:** 1 TB (Archivos pesados / Logs históricos).
*   **S.O.:** Debian Server.

---

## 🚀 Estrategia de Recursos (8GB RAM Optimization)

Con 8GB de RAM, **Ollama (IA Local)** es el enemigo principal de la estabilidad. Modelos como Qwen-7B consumen ~5GB, dejando solo ~2.8GB para el Kernel de Debian y el Motor de RED de OsintUltimate. Bajo una inundación de paquetes o un escaneo masivo, el sistema entrará en *thrashing* (swap masivo en HDD) y colapsará.

### 1. IA Híbrida (Student Pack Edition)
Para liberar memoria, moveremos el "Cerebro" de la IA a la nube de forma gratuita:
- **Azure OpenAI (Student Benefit)**: Usa los $100 de crédito para **GPT-4o-mini**. No consume RAM local y es 10x más rápido que tu i3.
- **Gemini Flash (Google AI Studio)**: Tier gratuito masivo. Ideal para análisis de reportes largos sin tocar tus 8GB de RAM.
- **Ollama (GPU Mode)**: Si necesitas IA local, debes instalar **ROCm** para que el modelo viva en la **VRAM** de la RX 580, no en la RAM del sistema.

### 2. Infraestructura Efímera (DigitalOcean Pack)
Usa los **$200 de crédito de DigitalOcean** para implementar la arquitectura de **Swarm (Enjambre)** que propuse en la auditoría v4.0:
- El nodo local (tus 8GB) actúa solo como **C2 Central**.
- Levanta 5-10 nodos "Scanning Droplets" (1 vCPU, 512MB RAM) en DO.
- **Ventaja**: Las IPs de escaneo son frescas (evitas bloqueos en tu IP residencial) y el tráfico pesado no ahoga tu red local.

### 3. Sandboxing Híbrido (Nuevo en v4.0)
Para evitar el colapso de la RAM al usar contenedores:
- El motor ahora usa **Hardware Tiering**. En tu máquina de 8GB, el sistema activa automáticamente el **Fluid Tier** (ejecución nativa con `ProcessGuard`).
- **Ahorro de RAM**: Evitas el overhead de múltiples daemons de Docker corriendo simultáneamente.
- **Seguridad Dirigida**: Solo las herramientas de **Explotación** usarán Docker (excepción de seguridad), manteniendo el resto del sistema fluido.

### 4. Optimización de Disco (SSD vs HDD)
- **SSD**: Solo para el ejecutable de Rust y la DB activa (`results.sqlite` o `RocksDB`).
- **HDD**: Solo para los backups de JSONL o el dump de tráfico `.pcap` masivo. Nunca corras la DB en el HDD durante un escaneo de 1,000+ targets.

---

## 🎓 Beneficios Estudiantiles Críticos para OsintUltimate

| Proveedor | Crédito | Uso Útil |
| :--- | :--- | :--- |
| **DigitalOcean** | $200 | Nodos de escaneo distribuidos, IP rotation. |
| **Microsoft Azure** | $100 | AI de alta velocidad (Azure AI Studio), VPS B1s gratis. |
| **Namecheap/.me** | 1 año c/u | Dominios para **Canary Tokens** y **Honeypot Mapping**. |
| **Frontend Masters** | 6 meses | Si quieres pulir el **Web Dashboard** de Axum con visualizaciones avanzadas. |
| **Canva (Base)** | 1 año | Para generar infografías y reportes de Red Team profesionales para clientes. |

---
> [!TIP]
> **ZRAM en Debian**: Si tienes activado el HDD como SWAP, desactívalo y usa **ZRAM**. Comprime la memoria RAM en tiempo real, lo que es mucho más rápido que escribir en el HDD de 1TB.
> `$ sudo apt install zram-tools`
