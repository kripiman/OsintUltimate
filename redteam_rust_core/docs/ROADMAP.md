# 🗺️ Hoja de Ruta de Desarrollo: OsintUltimate v3.0

Esta hoja de ruta está diseñada para transicionar el proyecto de un "reemplazo de scripts" a una "Plataforma de Grado Empresarial".

## 📅 Fase 1: Fortalecimiento (Semanas 1-2)
*Enfoque: Estabilidad, Pruebas y Gestión de Recursos*

- [x] **Corregir Modelo de Concurrencia**: Refactorizar el `Orchestrator` para usar contrapresión basada en `Stream` en lugar de saturación con `tokio::spawn`. (V9/V10 Fixes)
- [x] **Añadir Pruebas Unitarias**: Cobertura básica para módulos centrales (`orchestrator.rs`, `utils/liveness.rs`). (Verificado en V10)
- [x] **Implementar Salida de Streaming**: Escribir hallazgos en `scan_result.jsonl` (JSON Delimitado por Líneas) en tiempo real. (ARCH-004 + V10 fixes)
- [x] **Enum TargetStatus**: Reemplazar el estado basado en strings con Enums estrictos. (V6)

## 🚀 Fase 2: Evolución de la Arquitectura (Semanas 3-4)
*Enfoque: Modularidad y Características Avanzadas*

- [x] **Patrón de Pipeline**: Abstraer la lógica multi-fase (Descubrimiento -> Liveness -> Ataque) en una estructura `Pipeline` configurable. (Completado en auditoría P2)
- [ ] **Carga Dinámica de Plugins**: Permitir la carga de plugins externos `.so` o `.dylib` (opcional, crea una extensibilidad extrema).
- [~] **Integración de Base de Datos**: *Cancelado por restricciones de RAM en el entorno de ejecución.* Mantendremos de forma exclusiva el formato JSONL de streaming nativo para máxima eficiencia.

## 🛡️ Fase 3: Sigilo y Evasión (Semanas 5-6)
*Enfoque: Capacidades Específicas de Red Team*

- [x] **Rotación Inteligente de Proxies**: Integrar la lógica de rotación más profundamente en el middleware de `reqwest` en lugar de solo en el pool de clientes.
- [x] **Modelado de Tráfico**: Implementar "Jitter" a nivel detallado de paquete/solicitud dentro del Orchestrator.
- [x] **Expansión de Reconocimiento Pasivo**: Añadir integración con APIs de Shodan/Censys en el `OsintScanner`.

## 📦 Fase 4: Distribución
*Enfoque: Usabilidad*

- [ ] **Dockerización**: `Dockerfile` optimizado (distroless/cc).
- [ ] **CI/CD**: GitHub Actions para `cargo test`, `cargo clippy` y construcciones de Release.
