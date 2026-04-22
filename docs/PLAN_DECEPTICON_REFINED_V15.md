# Documentación Técnica: Decepticon Refined (V15.0)

Este documento detalla la arquitectura y el diseño técnico del Pipeline Anti-Alucinación y el RAG Tool Optimizer.

## 1. Pipeline Anti-Alucinación (Validation Engine)

Inspirado en NeuroSploit, este motor tiene como objetivo eliminar los falsos positivos generados por el razonamiento creativo (alucinación) de los LLM durante la validación de vulnerabilidades.

### 1.1 — Arquitectura de Tres Capas

| Capa | Nombre | Función |
| --- | --- | --- |
| 1 | **Negative Controls** | Envía una petición "sana" (sin payload) al endpoint para comparar la respuesta base. |
| 2 | **Proof of Execution** | Verifica señales técnicas (Status Code, Regex match, Time delay o ejecución en navegador). |
| 3 | **Confidence Scorer** | Un LLM de alto razonamiento evalúa las capas anteriores y asigna un puntaje de 0 a 100. |

### 1.2 — Lógica de Decisión (Rust)

```rust
pub enum ValidationStatus {
    Verified,    // Confirmed proof of concept
    Suspicious,  // High score but no technical proof
    PseudoFalse, // Same behavior as negative control
    Rejected,    // Clear hallucination or error
}
```

## 2. RAG Tool Optimizer (Context Management)

El objetivo es permitir que `OsintUltimate` escale a cientos de plugins sin desbordar la ventana de contexto del LLM.

### 2.1 — Flujo de Trabajo

1. **Indexing**: Al inicio, se generan embeddings de todos los metadatos de los plugins.
2. **Querying**: Cuando el router necesita decidir una acción (`decide_action`), utiliza el `finding` actual como consulta.
3. **Filtering**: Se recuperan solo los mejores `K` plugins (ej. Top 20).
4. **Injection**: La lista reducida se inyecta en el prompt del sistema.

### 2.2 — Beneficios Esperados

- **Ahorro de Tokens**: Reducción de hasta un 80% en prompts de decisión.
- **Precisión**: Menos confusión para el modelo al tener menos opciones irrelevantes.
- **Escalabilidad**: Capacidad para manejar miles de herramientas MCP sin latencia significativa.

--
*Generado automáticamente para OsintUltimate v15.0.*
