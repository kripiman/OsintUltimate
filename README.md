# 🛡️ OsintUltimate (V13 Stealth Hardening Protocol)

> **Motor de Evaluación de Red Team de Alto Rendimiento, Asíncrono y Autónomo**
> 
> *Sigilo Absoluto. Seguridad Atómica. Concurrencia Lock-Free.*
> *Arquitectura V13: Infraestructura Stealth, I/O io-uring y Agente Sentinel.*

---

## 🚀 Vista General

**OsintUltimate V13** es la evolución definitiva del motor de Red Team, diseñado para operaciones encubiertas de alta intensidad. Esta versión introduce una infraestructura de sigilo autoconsciente y un pipeline de red ultra-eficiente basado en `io-uring`.

### Novedades en V13:
- **Infraestructura Stealth Autónoma**: Detección nativa de Oracle Cloud (OCI) y despliegue automático de proxies en DigitalOcean para evasión de IP.
- **Egress Hardening Rígido**: Validación semántica de argumentos y Pinning de IP obligatorio en `PocValidator` para prevenir DNS Rebinding.
- **Pipeline Lock-Free**: Ingesta de resultados mediante `SegQueue` desacoplada, eliminando bloqueos de base de datos durante escaneos masivos.
- **Native io-uring Scanner**: Escaneo de red de alto rendimiento que bypassa el modelo `fork/exec` utilizando `SQPOLL` en el kernel de Linux.
- **Agente Sentinel V13**: IA táctica con capacidad de validación de PoC intrusivos bajo control manual (`Approval Gate`).

---

## 📚 Documentación Técnica (Single Source of Truth)

Consulta los documentos maestros para profundizar en el diseño:

*   [🏗️ Arquitectura V13 (Master)](redteam_rust_core/docs/ARCHITECTURE.md): Diseño asíncrono, flujos de concurrencia y diagramas Mermaid.
*   [🕵️ Infraestructura Stealth](redteam_rust_core/docs/STEALTH_INFRA.md): Detección OCI, proxies DigitalOcean y control de egress.
*   [📊 Esquema de Persistencia](redteam_rust_core/docs/PERSISTENCE_SCHEMA.md): Detalles del esquema SQLite y motor lock-free.
*   [🛡️ Hardening y SIGILO](redteam_rust_core/docs/HARDENING_AND_OPSEC.md): Protocolos de evasión, jitter adaptativo y seguridad OPSEC.
*   [🧠 Orquestación de IA (Sentinel)](redteam_rust_core/docs/AI_ORCHESTRATION.md): Tiered AI Router y toma de decisiones autónoma.
*   [🧩 Desarrollo de Plugins](redteam_rust_core/docs/PLUGIN_DEVELOPMENT.md): Guía para extender las capacidades del núcleo.

---

## 💻 Requisitos del Sistema

### Hardware (Optimización Dinámica)
OsintUltimate V13 se adapta automáticamente a tu hardware para garantizar estabilidad:

| Recurso | Mínimo (Modo UltraLow) | Recomendado (Enterprise) |
| :--- | :--- | :--- |
| **CPU** | Dual-core (x86_64/ARM64) | Quad-core o superior |
| **RAM** | 1 GB | 8 GB+ |
| **Disco** | SSD (Indispensable para WAL) | NVMe SSD |
| **Red** | 10 Mbps (Baja latencia) | 1 Gbps+ |

---

## 🛠️ Instalación y Construcción

```bash
git clone https://github.com/kripiman/OsintUltimate
cd OsintUltimate/redteam_rust_core
cargo build --release
```

El binario optimizado estará en `target/release/redteam_rust_core`.

---

## 🛡️ Características Principales V13

-   **⚡ Alto Rendimiento**: Impulsado por `tokio` e `io-uring`. Escanea miles de hosts con una huella de memoria mínima (~20MB RAM).
-   **🕵️ Evasión Avanzada**: 
    - Jitter Log-Normal (comportamiento humano).
    - Rotación de identidades (User-Agents y TLS Fingerprinting).
    - Thompson Sampling para selección de payloads WAF.
-   **🔒 Seguridad por Diseño**:
    - Garantías de seguridad de Rust (Memory Safety).
    - Protección SSRF estricta contra rangos privados y metadatos cloud.
    - Sandboxing híbrido (Docker vs ProcessGuard) basado en RAM disponible.
-   **🤖 Sentinel AI Agent**: Pentesting autónomo con orquestación de LLMs en cascada (Gemini Pro/Claude/OpenAI).

---

## 📜 Licencia

Privado y Confidencial - Solo para uso interno del Red Team.
© 2026 RedTeam Lab | OsintUltimate V13
