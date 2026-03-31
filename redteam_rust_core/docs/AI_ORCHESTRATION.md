# 🧠 Orquestación de IA y Agentes Autónomos (Sentinel)

OsintUltimate v3.0 integra un sistema avanzado de inteligencia artificial para elevar el pentesting de una simple ejecución de herramientas a una **toma de decisiones estratégica**.

---

## 1. `TieredAIRouter` (Cascada de IA Nativa)

La arquitectura de IA en OsintUltimate es jerárquica y eficiente en costos, diseñada para maximizar el razonamiento y minimizar el consumo de tokens y créditos de API.

### Niveles de Ruta (`RouteLevel`)

| Nivel | Modelo Sugerido | Uso | Costo |
| :--- | :--- | :--- | :--- |
| **Local** | `qwen2.5-coder:7b` | Triaje rápido, hallazgos informativos, falsos positivos comunes. | $0 (Autohospedado vía Ollama) |
| **Mid** | `gemini-1.5-flash` | Análisis de vulnerabilidades web, correlación de cabeceras, sugerencias de Nmap. | Bajo (Centavos / millón tokens) |
| **Premium** | `gemini-1.5-pro` | Cadenas de ataque críticas, explotación de AD, bypass de WAF complejo, reporte ejecutivo. | Medio/Alto |

### Optimización de Contexto (`ContextCompressor`)

OsintUltimate **comprime** los datos antes de enviarlos a la IA:
1.  **Truncamiento de Cuerpo**: Los cuerpos HTTP se cortan a 512 bytes para conservar la esencia técnica sin agotar la ventana de contexto.
2.  **Filtrado de Cabeceras (Whitelist)**: Solo se envían cabeceras relevantes para la seguridad (`Server`, `CSP`, `Sec-Headers`, etc.).
3.  **Deduplicación de Evidencia**: Si un hallazgo es idéntico a uno ya analizado, la IA no se consulta gracias a la `analysis_cache` persistente (vía `moka`).
4.  **Structured Distillation (v3.1)**: En lugar de enviar texto de `--help` crudo, el motor extrae esquemas JSON optimizados, permitiendo a la IA entender las flags exactas de herramientas BlackArch complejas.

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

## 3. Caché Táctica Supervisada

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

# Gemini (Premium Tier)
GEMINI_API_KEY="tu-clave-gemini"
```

---

© 2026 RedTeam Lab | OsintUltimate v3.0 Documentation
