# 🧠 Orquestación de IA y Agentes Autónomos (Sentinel)

OsintUltimate v4.0 integra un sistema nativo de inteligencia artificial para elevar el pentesting de una simple ejecución de herramientas a una **toma de decisiones estratégica autónoma**.

---

## 1. `TieredAIRouter` (Cascada de IA Nativa)

La arquitectura de IA en OsintUltimate es jerárquica y eficiente en costos, diseñada para maximizar el razonamiento y minimizar el consumo de tokens y créditos de API.

### Niveles de Ruta (`RouteLevel`)

| Nivel | Modelo Sugerido | Uso | Costo |
| :--- | :--- | :--- | :--- |
| **Local** | `qwen2.5-coder` | Triaje rápido, hallazgos informativos, falsos positivos comunes. | $0 (Ollama) |
| **Mid** | `GPT-4o-mini`, `Gemini Flash` | Análisis de vulnerabilidades web, correlación de cabeceras, sugerencias de Nmap. | Bajo |
| **Premium** | `Claude 3.5 Sonnet`, `GPT-4o`, `Gemini Pro` | Cadenas de ataque críticas, bypass de WAF complejo, reporte ejecutivo. | Medio/Alto |

### Optimización de Contexto (`ContextCompressor`)

OsintUltimate **comprime** los datos antes de enviarlos a la IA:
1.  **Truncamiento de Cuerpo**: Los cuerpos HTTP se cortan a 512 bytes para conservar la esencia técnica sin agotar la ventana de contexto.
2.  **Filtrado de Cabeceras (Whitelist)**: Solo se envían cabeceras relevantes para la seguridad (`Server`, `CSP`, `Sec-Headers`, etc.).
3.  **Deduplicación de Evidencia**: Si un hallazgo es idéntico a uno ya analizado, la IA no se consulta gracias a la `analysis_cache` persistente.
4.  **Structured Distillation**: En lugar de enviar texto de `--help` crudo, el motor extrae esquemas JSON optimizados, permitiendo a la IA entender las flags exactas de herramientas BlackArch complejas. **Optimizado nativamente en Rust.**

---

## 2. Agente Autónomo `Sentinel`

Activado con el flag `--autonomous`, el sistema activa el **Modo Autopiloto**.

### El Ciclo de Decisión de Sentinel:
1.  **Ingesta**: Un hallazgo aparece (ej. Puerto 80 abierto con Apache).
2.  **Cascada**: El `TieredAIRouter` envía el hallazgo con contexto comprimido al nivel de IA correspondiente.
3.  **Razonamiento**: La IA analiza el hallazgo y genera un objeto `AIAnalysis`.
4.  **Decisión**: La IA propone la **siguiente acción táctica**. 
    - *Ejemplo*: "He detectado una versión vulnerable de Apache. Recomiendo lanzar el plugin `nuclei_scanner` con el template `cve-2021-41773`."
5.  **Ejecución**: El orquestador inyecta dinámicamente la tarea sugerida en el pipeline de ejecución, cerrando el ciclo.

### 🛡️ Sentinel en Evasión (Fase de Escalación)
Cuando un objetivo devuelve un error 403 (WAF detectado), Sentinel activa la **Etapa 3 de Evasión**:
- El agente recibe el mensaje de error del WAF y el payload original.
- Utiliza **Ollama Local** (para mantener OPSEC) para generar una variante del payload que eluda la firma detectada.
- El orquestador reintenta la petición con el nuevo "Advice" táctico inyectado.

---

## 3. Enrutamiento y Fallback Multicloud

El `TieredAIRouter` no solo selecciona un nivel, sino que gestiona una lista de **Proveedores Genéricos** (`LlmProviderKind`) con prioridades específicas.

### Mecanismo de Resiliencia:
1.  **Prioridad Intra-Nivel**: Dentro de un mismo tier (ej. Premium), el router intenta primero el proveedor con `priority: 0` (ej. Claude 3.5 Sonnet). Si este falla (rate limit, error 500), pasa automáticamente al siguiente (ej. GPT-4o).
2.  **Escalación de Tier**: Solo si todos los proveedores de un nivel seleccionado fallan, el motor escala la petición al siguiente nivel superior.
3.  **Anotación de Modelo**: Cada hallazgo analizado incluye metadatos sobre qué proveedor y qué tier exacto generó el análisis (ej. `Claude 3.5 (Tiered: Premium, Provider: Anthropic)`).

---

## 4. Caché Táctica Supervisada

OsintUltimate utiliza dos cachés críticas para ahorrar tokens y tiempo:
- **`analysis_cache`**: Almacena el análisis de vulnerabilidades único por host/hallazgo (TTL 2h).
- **`decision_cache`**: Almacena las decisiones tácticas (qué plugin lanzar a continuación) (TTL 30m).

Si el sistema detecta que un hallazgo similar ya ha sido analizado en la última hora, **reutiliza el análisis**, garantizando un rendimiento masivo sin costos de API descontrolados.

---

## 4. Configuración de API Keys

El sistema busca las siguientes variables de entorno en el archivo `.env`:

```env
# Ollama (Local)
OLLAMA_URL="http://localhost:11434"

# Azure OpenAI (Mid Tier)
AZURE_OPENAI_ENDPOINT="https://tu-endpoint.openai.azure.com/"
AZURE_OPENAI_KEY="tu-clave-azure"

# OpenAI (Generic)
OPENAI_API_KEY="sk-..."

# Anthropic (Generic)
ANTHROPIC_API_KEY="sk-ant-..."

# Gemini (Premium Tier - Multi-key redundancy support)
GEMINI_API_KEYS="clave1,clave2,clave3"
GEMINI_API_KEY="clave_unica_fallback"
```

---

## 5. Pipeline de Validación de PoC (v4.0)

Sentinel integra un motor de validación para confirmar hallazgos mediante la ejecución de exploits seguros.

### Estrategias de Validación:
- **ShellCommand**: Comandos de sistema (ej. `id`, `whoami`) ejecutados con timeouts estrictos.
- **HttpPayload**: Peticiones web específicas para confirmar inyecciones o archivos expuestos.
- **NucleiTemplate**: Uso de plantillas Nuclei generadas dinámicamente.

### Interacción con el Dashboard:
Para PoCs marcados como **intrusivos**, el sistema se bloquea y lanza una solicitud al Dashboard:
1. El operador visualiza la acción propuesta, el riesgo y el payload.
2. Tras la aprobación vía API (`POST /api/v1/approvals/:id/decision`), Sentinel procede con la ejecución.
3. Los resultados se reflejan en tiempo real, marcando el hallazgo como `verified: true` en el reporte final.

---

© 2026 RedTeam Lab | OsintUltimate v4.0 Documentation
