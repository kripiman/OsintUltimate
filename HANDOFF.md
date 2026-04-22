### Sovereign Hardening & Sync V14.8

He verificado los hallazgos del informe comparativo y el fallo en los tests de `MCP-OSINTULT`:

- **to_ascii_safe()**: Implementado en el servidor de desarrollo, pero ausente en el core ofensivo (Validado).
- **FillerRemover**: El bug de las preposiciones afecta solo a `MCP-OSINTULT`. `OsintUltimate` ya está limpio (Validado).
- **test_sequential_optimization**: Falla en `MCP-OSINTULT` por falta de mapeos de sinónimos ("security" -> "sec") y el impacto de Wenyan (Validado).

**Preguntas Abiertas:**
1. ¿Usamos los mismos umbrales de tokens para `route_task` (30k/100k) en el core ofensivo?
2. Además de eliminar los fillers, ¿añado el mapeo de "security" -> "sec" en `MCP-OSINTULT` para que pase el test, o prefieres actualizar la aserción?

He creado el **Implementation Plan** con los detalles técnicos. Quedo a la espera de tu aprobación para proceder.