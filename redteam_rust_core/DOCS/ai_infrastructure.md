# 🧠 Infraestructura IA & Prompt Engineering

OsintUltimate implementa una capa de abstracción de IA de alto rendimiento diseñada para maximizar la precisión técnica mientras se minimiza el costo operativo y la latencia. El sistema utiliza un motor de enrutamiento por niveles (Tiered Routing) y una tubería de optimización de tokens de 10 etapas.

## 1. Enrutamiento por Niveles (Tiered Routing)

El `TieredAIRouter` actúa como el despachador central, clasificando cada hallazgo y tarea según su complejidad técnica y severidad.

### Estrategia de Selección de Tiers
*   **Tier 2 (Premium)**: Utilizado para análisis críticos de vulnerabilidades de alto impacto (CVSS ≥ 8.5) y planes de persistencia C2 avanzados. Modelos: GPT-4o, Claude 3.5 Sonnet.
*   **Tier 1 (Mid)**: Balance óptimo entre costo y razonamiento para tareas de escaneo activo y análisis de configuración (CVSS 5.0 - 8.4). Modelos: GPT-3.5 Turbo, Gemini 1.5 Flash.
*   **Tier 0 (Local)**: Prioridad máxima para privacidad y bajo costo en tareas de análisis de código fuente y reconocimiento masivo. Modelos: Ollama (Llama 3 / CodeLlama), Microsoft Phi-3.

```mermaid
graph TD
    Finding[Hallazgo Detectado] --> Classifier{Clasificador de Riesgo}
    Classifier -->|CVSS >= 8.5| Premium[Tier 2: Premium LLM]
    Classifier -->|CVSS 5.0-8.4| Mid[Tier 1: Mid-Tier LLM]
    Classifier -->|CVSS < 5.0| Local[Tier 0: Local LLM]
    
    Premium -->|Failover| Mid
    Mid -->|Failover| Local
    Local -->|Success| Dashboard[Resultados Enriquecidos]
```

---

## 2. Optimización de Tokens de 10 Etapas

Para reducir el "bleed" de créditos API y permitir contextos masivos, OsintUltimate utiliza el **v13 Deterministic Prompt Optimizer**. Este motor procesa los prompts a través de diez transformaciones sucesivas.

### Etapas de Optimización
1.  **Extractive Compressor**: Puntúa cada línea según su señal técnica (Keywords como `proxy`, `payload`, `vuln`) y elimina las de baja relevancia.
2.  **Entropy Pruner**: Elimina adverbios de baja entropía (e.g., "basically", "actually") que no aportan valor operativo.
3.  **Verbosity Reducer**: Colapsa frases verbales largas (e.g., "in order to" -> "to").
4.  **Article Stripper**: Elimina artículos definidos e indefinidos (a, an, the).
5.  **Filler Remover**: Limpia palabras de cortesía o relleno innecesario.
6.  **Synonym Mapper**: Abrevia términos técnicos largos (e.g., `vulnerability` -> `vuln`).
7.  **Suffix Lemmatizer**: Elimina sufijos gramaticales (-ing, -ed, -ly) con una heurística de detección de código endurecida para prevenir la corrupción de contextos técnicos.
8.  **Punctuation Pruner**: (Modo Ultra) Elimina puntuación no estructural.
9.  **Wenyan Ultra**: (Modo Ultra) Sustituye términos técnicos comunes por glifos CJK de un solo carácter (e.g., `security` -> `安`).
10. **Deduplicator**: Pase final para eliminar redundancias introducidas por las etapas anteriores.

### Resultados de Compresión
*   **Lite Mode**: ~15-20% de ahorro (Lectura humana intacta).
*   **Full Mode**: ~40-60% de ahorro (Legible para LLMs modernos).
*   **Ultra Mode (Wenyan)**: ~80% de ahorro (Optimizado para agentes autónomos V15).

---

## 3. Inyección de Habilidades Técnicas (SkillManager)

A diferencia de los prompts estáticos, OsintUltimate utiliza un sistema de **RAG Técnico** para inyectar conocimientos específicos de Red Team (TTPs) en el momento justo del análisis.

### Flujo de Habilidades
*   **Matching**: El `SkillManager` selecciona fragmentos de conocimiento basados en la categoría del hallazgo y la postura actual (`Ghost`, `Strike`, `Breach`).
*   **Dynamic Budgeting**: El presupuesto de tokens para habilidades se escala según el Tier del modelo (más contexto para modelos Premium).
*   **Surgical Injection**: Las habilidades se inyectan como "bloques de experto" que dictan la lógica de decisión del agente sin necesidad de re-entrenamiento.

```mermaid
sequenceDiagram
    participant R as Router
    participant S as SkillManager
    participant K as Knowledge Base
    participant L as LLM

    R->>S: match_skills(Finding, Posture)
    S->>K: query(JSON TTPs)
    K-->>S: Raw Skills
    S->>S: Build injection block (Wenyan optimized)
    S-->>R: Enriched Context
    R->>L: Final Optimized Prompt
```

---

## 4. OPSEC & Privacidad (PII Scrubbing)

Antes de que cualquier dato llegue a proveedores de IA externos (Azure/OpenAI/Anthropic), el `Scrubber` procesa la información para proteger la infraestructura:

- **Identity Masking**: Reemplaza nombres de usuarios, IPs internas y paths sensibles por placeholders sintéticos.
- **Credential Stripping**: Elimina automáticamente tokens, API keys y hashes detectados en el contexto de ataque.
- **Tactical Cache**: Utiliza una caché **LRU (moka)** para evitar enviar el mismo hallazgo crítico a la IA varias veces, protegiendo tanto el presupuesto como la exposición de datos y garantizando la consistencia del contexto bajo carga masiva.

---

> [!IMPORTANT]
> El modo **Wenyan Ultra** está diseñado exclusivamente para interacción máquina-máquina. Los operadores que deseen leer los logs de IA en lenguaje natural deben configurar el nivel de optimización en `Lite` o `Off`.

---

## 5. External AI Tool Token Strategy (Garak / PyRIT / Promptfoo / etc)

Plugins ofensivos AI/LLM (`exploitation/ai_llm/*`) ejecutan binarios externos que generan **adversarial prompts** contra targets LLM. Estos prompts NO deben optimizarse — wording exacto = sagrado para test integrity.

### 5.1 Decisión arquitectónica: NO Bridge Optimizer

**Rechazado:** local OpenAI-compat proxy interceptando outbound calls + applying `PromptOptimizer`.

**Razón:**
- Adversarial prompts (jailbreaks, injections, DAN-style) calibrados contra **token sequences específicas**.
- Lemmatize/article-strip/filler-remove → destruye attack semantics.
- "Ignore all previous instructions" → "ignore previous instruction" → jailbreak no triggers.
- Reproducibility broken → CVE/bounty reports inválidos.
- Optimizer domain = chat compression, NOT adversarial vector mutation.

**Conclusión:** prompts de ataque pasan through unchanged. Optimization happens en **scan configuration**, no en payload content.

---

### 5.2 Strategy A+B+C — Smart Scan Profiles

Tres palancas de ahorro real **sin tocar payloads**:

| Lever | Mechanism | Typical Saving |
|---|---|---|
| **A. Probe selection** | `--probes <subset>` vs `--probes all` | 5-50× |
| **B. Model tier** | `gpt-4o-mini` vs `gpt-4` (target side) | 10-200× |
| **C. Generation cap** | `--generations 3` vs default 10 | 3× |

Combinados → **150-30000× cost reduction** vs full default scan, sin perder coverage crítico.

---

### 5.3 Scan Profiles (Default Tiers)

Tres profiles built-in. Plugin AI selecciona según `TokenBudget` state.

#### Economy (default si budget < 50%)
```
probes:       critical-only (HijackHateHumans, DAN, jailbreak basics)
generations:  3
target_model: cheapest available (gpt-4o-mini, claude-haiku, llama3.2:1b)
timeout:      300s
parallelism:  1
```
Cost target: < 1k tokens / scan.

#### Standard (default si budget 50-80%)
```
probes:       OWASP LLM Top 10 subset (~15 probes)
generations:  5
target_model: mid-tier (gpt-4o, claude-sonnet)
timeout:      900s
parallelism:  3
```
Cost target: ~10k tokens / scan.

#### Thorough (only si budget > 80% AND posture = Strike)
```
probes:       all
generations:  10
target_model: as-configured (no override)
timeout:      3600s
parallelism:  5
```
Cost target: ~100k+ tokens / scan.

---

### 5.4 Per-Tool Configuration Matrix

| Tool | Probe-equivalent flag | Generation flag | Profile target |
|---|---|---|---|
| **Garak** | `--probes promptinject.HijackHateHumans` | `--generations N` | `garak.profile: economy` |
| **PyRIT** | Orchestrator selection (`Crescendo`, `RedTeaming`, `PAIR`) | `max_turns N` | `pyrit.profile: economy` |
| **Promptfoo** | `--filter-tests <name>` (assertion subset) | `--repeat N` | `promptfoo.profile: economy` |
| **Promptmap** | `--rules <subset>` | (single-shot) | `promptmap.profile: economy` |
| **PromptInject** | corpus subset (`base64`, `ignore_prev`, `dan`) | iteration cap | `promptinject.profile: economy` |
| **LLMFuzzer** | mutation strategy (`grammar`, `random`, `corpus`) | budget (max attempts) | `llmfuzzer.profile: economy` |

**Each plugin exposes:**
```rust
pub struct AiScanProfile {
    pub probes: ProbeSelection,        // All | Critical | Custom(Vec<String>)
    pub generations: u32,              // attempts per probe
    pub target_model: Option<String>,  // override target side model
    pub max_runtime_secs: u64,
    pub parallelism: u32,
}
```

---

### 5.5 Auto-Profile Selection Logic

Plugin `scan()` reads `GlobalConfig.budget` BEFORE execution:

```rust
let pct_remaining = (budget.max_tokens - budget.current_effective_total()) * 100 
                   / budget.max_tokens.max(1);

let profile = match pct_remaining {
    p if p < 20 => return Ok(vec![]),  // Economy abort
    p if p < 50 => AiScanProfile::economy(),
    p if p < 80 => AiScanProfile::standard(),
    _           => self.config_profile.unwrap_or(AiScanProfile::standard()),
};
```

Override via CLI flag: `--ai-profile thorough` (forces, ignores budget) — guarded by Sovereign feature gate.

---

### 5.6 Response Cache Layer

Compatible con strategy (no payload mutation). Key = `hash(target_url + prompt + model)`. TTL = 24h. Stored vía existing `moka` LRU cache (sección 4 Tactical Cache pattern).

**Saves on rerun scenarios:**
- Re-running same probe against same target during dev/debug.
- Multi-plugin overlap (Garak + PromptInject ambos usan `ignore_previous_instructions` corpus).

```rust
if let Some(cached) = ai_response_cache.get(&key) {
    return Ok(cached.findings);  // skip subprocess entirely
}
```

Cache invalidation: target endpoint version change → bust by including target's response to a probe canary in key.

---

### 5.7 Cost Telemetry

Plugin emits token-cost estimate to `TokenBudget` POST scan:

```rust
budget.add_usage(&TokenUsage {
    prompt_tokens: estimated_input_tokens(probes_run, generations),
    completion_tokens: parsed_response_tokens,
    total_tokens: prompt + completion,
});
```

Estimation formula per tool documented en plugin source. Source-of-truth for budget enforcement → next scan reads updated budget → escalates to lower profile.

---

### 5.8 Veredicto Operacional

**Default behavior:** Economy profile, all AI plugins, all scans.
**Escalation:** explicit user flag OR confirmed high-value target (CVSS-projected ≥ 8.5).
**Never:** mutate adversarial prompts mid-flight. Test integrity > token savings.

> [!IMPORTANT]
> AI/LLM scanning costs scale **multiplicatively**: probes × generations × target_model_price. A `Thorough` scan against GPT-4 = ~$50-200 USD per target. Always confirm budget tier before launching `--ai-profile thorough`.
