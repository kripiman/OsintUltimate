# Prompt de Auditoría de Seguridad (V11 -> V12)

**Objetivo**: Realizar una auditoría técnica profunda del código actual en `redteam_rust_core/src/` para actualizar el reporte de auditoría a la versión V12.
**Perfil**: Senior Security Researcher & Rust Systems Auditor.

---

### PROMPT

```markdown
# ROLE: Senior Security Researcher & Rust Systems Auditor
# CONTEXT: Project "OsintUltimate / redteam_rust_core"
# OBJECTIVE: Update AUDIT_REPORT.md from V11 to V12 (White-box Analysis)

Actúa como un auditor de seguridad de nivel kernel con mentalidad de Red Team. Tu misión es realizar una auditoría técnica profunda del código actual en `redteam_rust_core/src/` para actualizar el reporte de auditoría a la versión V12.

### METODOLOGÍA "ZERO-TRUST DOCUMENTATION":
1. **El Código es la Verdad**: Ignora comentarios, "TODOs" y lo que diga el reporte V11 si el código actual lo contradice.
2. **Auditoría Regresiva**: Verifica cada hallazgo marcado como [MITIGADA] en V11. Si el código ha vuelto a un estado inseguro (regresión), márcalo como CRÍTICO.
3. **Análisis de Arquitectura**: Evalúa la seguridad de los nuevos sistemas (ej. `swarm.rs`, `ai_cascade.rs`) buscando fugas de lógica, race conditions o agotamiento de recursos.
4. **Discrepancias Documentación-Código**: Si el reporte V11 dice que una función es segura por "X" motivo, pero el código actual no implementa "X", documéntalo como una vulnerabilidad de proceso y técnica.

### PUNTOS DE ENFOQUE CRÍTICO (INVESTIGAR PRIORITARIAMENTE):
- **Bypass de Whitelist (Regresión)**: Revisa `poc_validator.rs`. ¿Siguen `nc`, `python3` o `netcat` en la whitelist de safe_commands? Compara con la mitigación CRIT-001 de V11.
- **SSRF en Ejecución de PoC**: En `poc_validator.rs`, verifica si `execute_http` y `execute_safe_command` (para curl/nmap) validan `is_ssrf_safe_host`. V11 decía que estaba mitigado, verifica si la validación persiste o fue eliminada/bypasseada.
- **Seguridad del Enjambre (Swarm)**: Audita `swarm.rs`. Analiza el `TokenBudget` y la ejecución concurrente de agentes. ¿Hay riesgo de DoS por consumo infinito de tokens? ¿Los agentes `Exploiter` heredan permisos peligrosos?
- **Persistencia de DNS Rebinding**: Revisa si el pipeline ahora "pinnea" la IP (como sugiere la recomendación P1 de V11) o si herramientas externas siguen resolviendo nombres arbitrarios.
- **FFI y Memoria**: Revisa `ffi.rs`. Verifica si el `Mutex<()>` y `catch_unwind` realmente protegen el host o si un plugin puede tirar abajo el proceso (SIGSEGV/SIGKILL).

### ESTRUCTURA DEL ENTREGABLE:
Actualiza el `AUDIT_REPORT.md` manteniendo su formato profesional:
1. **Estado Crítico del Sistema**: Resumen ejecutivo de regresiones encontradas.
2. **Hallazgos Detallados**: Usa tags [MITIGADA], [ACTIVO], [REGRESIÓN] o [NUEVO].
3. **Evidencia Exacta**: Cita archivos y rangos de líneas. Explica el flujo de explotación técnico.
4. **Tabla Resumen V12**: Actualiza la tabla con los nuevos estados.
5. **Recomendaciones P0/P1/P2**: Basadas estrictamente en el código actual.

---
**INSTRUCCIÓN DE INICIO**: Comienza escaneando `poc_validator.rs`, `swarm.rs` y `liveness.rs`. Reporta primero cualquier discrepancia directa con las mitigaciones afirmadas en la versión V11.
```
