# 🗺️ Hoja de Ruta de Desarrollo: OsintUltimate v3.0

Esta hoja de ruta detalla la evolución de OsintUltimate de un motor asíncrono básico a una **Plataforma de Operaciones de Red Team Autónoma y Profesional**.

---

## ✅ Fase 1: Estabilización y Rendimiento (Completado)
*Enfoque: Arquitectura asíncrona y seguridad de memoria.*

- [x] **Motor Asíncrono Puro**: `Tokio` + `Futures` (Sustitución total de Python).
- [x] **Streaming Persistence**: Escritura `JSONL` línea a línea para evitar OOM.
- [x] **Liveness & SSRF Shield**: Resolución DNS masiva con protección de red interna.
- [x] **Capability Layers**: Sistema de capas de riesgo (Passive, Discovery, Scanning, etc.).

## ✅ Fase 2: Profesionalización y Sigilo (Completado)
*Enfoque: Evasión (OPSEC) y Control de Recursos.*

- [x] **Human Jitter**: Distribución LogNormal para evadir detección de WAF.
- [x] **PGID Sandboxing**: Gestión segura de procesos externos (`ProcessGuard`).
- [x] **Memory Monitoring**: Backpressure y control de RAM en VPS de 1GB.
- [x] **Approval Gates**: Flujo de trabajo con autorización multinivel y auditoría.
- [x] **Soporte SQLite**: Persistencia relacional además de JSONL.

## 🧠 Fase 3: Inteligencia y Autonomía (v3.1 - En curso)
*Enfoque: IA Generativa y Agentes Autónomos.*

- [x] **Tiered AIRouter**: Orquestación de IA (Ollama / Flash / Pro) con caché táctica.
- [x] **Sentinel AI Agent**: Modo autónomo (`--autonomous`) para toma de decisiones tácticas.
- [x] **Context Compression**: Optimización de evidencia para ahorro masivo de tokens.
- [x] **Attack Graph Correlation**: Correlación automática de hallazgos para identificar cadenas de ataque complejas.
- [x] **ML-based False Positive Filter**: Clasificador local para reducir ruido en reportes.

## 📦 Fase 4: Ecosistema y Despliegue (Próximamente)
*Enfoque: Extensibilidad y DevOps.*

- [x] **Dynamic Plugin Loader**: Carga de plugins `.so` / `.dylib` en caliente.
- [x] **BlackArch Integration**: Detección y uso automático de herramientas del sistema.
- [x] **Dockerization**: Imagen optimizada (`distroless`) con todas las dependencias.
- [x] **CI/CD Integration**: Templates para GitHub Actions y Azure DevOps (SARIF export).
- [ ] **Web Dashboard**: Interfaz en tiempo real para monitoreo de escaneos masivos.

---

© 2026 RedTeam Lab | OsintUltimate v3.0 Roadmap
