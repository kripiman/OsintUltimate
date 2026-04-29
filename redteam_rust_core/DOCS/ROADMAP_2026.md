# 🗺️ ROADMAP 2026: OsintUltimate (Bug Bounty Edition)

Este documento detalla la hoja de ruta estratégica para la evolución de **OsintUltimate** durante 2026. Basado en un análisis riguroso de ROI en plataformas profesionales (Intigriti, HackerOne, Bugcrowd), el motor se divide en dos modos de compilación para maximizar los payouts y proteger el perfil del operador de baneos preventivos.

---

## 🏗️ Decisión Arquitectónica: Compile-Time Feature Flags

Para operar legalmente y sin fricciones en Bug Bounty, el núcleo (`redteam_rust_core`) implementa flags en `Cargo.toml`. Esto asegura que los triagers no vean herramientas de *Post-Explotación* o *C2* al auditar el repositorio o los payloads.

```toml
[features]
default = ["bug-bounty"]
bug-bounty = [] # Plugins 100% legales (Recon, API, Modern Web)
sovereign = ["bug-bounty"] # Activa C2, AD, y Explotación Destructiva
```

> [!WARNING]  
> **KILL-TIER (Fuera de Scope BB)**: Herramientas como *Mythic, Nimplant, Donut, Evilginx3, nanodump o Volatility3* **solo** compilarán bajo el flag `sovereign`. Nunca deben usarse en programas de Bug Bounty.

---

## 💸 FASE 1: *Money Phase* (Alta Sinergia Bug Bounty)
El enfoque absoluto está en la superficie web moderna y lógica de APIs (ej. programas como AS Watson).

| Categoría | Tool 2026 | Estado | Integración OsintUltimate (ROI) |
|---|---|---|---|
| **API Attack Chain** | **Akto** | *Pendiente* | Detección pasiva de BOLA/BFLA (Clase #1 de Payouts 2026). |
| **GraphQL 攻** | **InQL + Graphw00f**| **LISTO** | Introspección y bypass profundo en esquemas GraphQL. Highs consistentes. |
| **JS Deep Mine** | **gospider + jsluice ext** | **LISTO** | Extracción de endpoints y secretos vía AST Parsing en JS bundles. |
| **Cache Deception** | **wcd-scanner** | **LISTO** | Envenenamiento y decepción de caché en apps detrás de CDNs. |
| **Modern Web Vuln**| **ppfuzz / ppmap** | **LISTO** | Cadenas de Prototype Pollution a XSS. Pago alto, baja competencia. |
| **CORS Misconfig** | **Corsy** | **LISTO** | Movido de Fase 2 a Fase 1 por alta sinergia. |

---

## 🚀 FASE 2: *Force Multiplier* (Automatización Continua)
Automatización para obtener la ventaja de ser el primero (First-finder advantage) en wildcards EU.

| Categoría | Tool 2026 | Estado | Integración OsintUltimate |
|---|---|---|---|
| **Continuous Monitor**| **certstream + chaos-diff** | **LISTO** | Demonio integrado en el motor Rust para descubrir subdominios en vivo. |
| **Auth Bypass** | **nomore403 ext / byp4xx** | **LISTO** | Bypass multitécnica de 403 para pivotar hacia paneles admin. |
| **Param Mining** | **x8 + Param Miner** | **LISTO** | Descubrimiento de parámetros ocultos (Lógica nativa en Rust). |
| **CORS Misconfig** | **Corsy** | **LISTO** | Cadenas de Account Takeover vía configuraciones CORS laxas. |
| **Sub-Takeover** | **domain-protect / nuclei** | **LISTO** | Takeovers masivos orientados a Cloud (S3, Azure, Heroku). |

---

## 🛠️ FASE 3: Mantenimiento y Extensiones Especializadas
Mantenimiento crítico y nichos específicos dependientes del "Scope" del programa.

| Categoría | Estrategia OsintUltimate | Estado | Contexto Bug Bounty |
|---|---|---|---|
| **Nuclei Core** | Auto-pull de repos (geeknik) | **EN PROGRESO** | Soporte para perfiles dinámicos y templates locales listo. |
| **SSRF Blind Chain** | **interactsh + ssrf-king** | **LISTO** | Enfoque en metadatos cloud (AWS IMDSv1). Critical instantáneo. |
| **AI / LLM** | **Garak / PyRIT** | *Pendiente* | **Solo usar** si el programa (ej. OpenAI, Anthropic) lo especifica. |
| **SAST / Supply** | **OSV-Scanner / Semgrep** | *Pendiente* | **Solo usar** si se descubre un `package-lock.json` expuesto. |

---

## ⚡ Lógica de Correlación (Auto-Chain)

El `CorrelationEngine` de OsintUltimate se ajustará para priorizar estas cadenas automatizadas en la Fase 1:

1. **La Cadena API (Chain ID: API-HUNT)**: `jsluice` extrae JS -> Encuentra GraphQL (`InQL`) -> Prototype Pollution (`ppmap`) -> CORS (`Corsy`). **Correlación nativa por Dominio en el motor.**
2. **La Cadena Prototype**: `x8` descubre parámetro oculto -> Dispara `ppmap` -> Si hay pollution -> **Alerta Medium/High**.
3. **La Cadena Cloud**: `certstream` detecta subdominio nuevo -> DNS resuelve NXDOMAIN -> Dispara `subzy` / `domain-protect` -> **Alerta Critical**.

> [!IMPORTANT]
> El objetivo es reducir la cantidad de escaneos inútiles y ruido, concentrando el poder de la infraestructura Oracle ARM en cadenas lógicas automatizadas que los escáneres comerciales no pueden replicar.
