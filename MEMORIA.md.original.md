# MEMORIA MCP-OSINTULT (SSOT)
Versión: V15.1.0 Sovereign Swarm (Bridge Mode)
Estado: PRODUCTION-READY
Estrategia: Hybrid Handoff (API as Primary, IDE Extension as Sovereign Failover)

## ARQUITECTURA V15.1 (SOVEREIGN)
- Claude Core (Surgical): Grounding reparado. Ejecución desde PROJECT_ROOT forzosa.
- Kimi Core (Volume): Respaldo en Kimi Code (IDE Extension) ante fallos de API.
- Handoff Prompt: Integrado con `/init` para optimizar contexto en Antigravity.

## BENCHMARKS
TOTAL_TOKENS_SAVED: 42500 (Base) + [Handoff Scaling]
Efficiency: MAX (Local execution does not consume API credits)
