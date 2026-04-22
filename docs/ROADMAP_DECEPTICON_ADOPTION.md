# Roadmap de Implementación: Adopción de Capacidades Decepticon en OsintUltimate V14.x

> Basado en análisis comparativo real del código fuente de ambos sistemas.
> Estado verificado: 2025-07

---

## Estado Actual Verificado

Tras leer el código real, el estado de partida es:

| Componente | Estado actual | Gap vs Decepticon |
|---|---|---|
| `Finding` struct | Tiene `cvss_score`, `mitre_attack`, `evidence` básico | Sin `cvss_vector`, `cwe[]`, `detected`, `remediation_priority`, evidencia con SHA-256 |
| `PolicyProvider` / `StaticPolicy` | PSL + Regex, carga `policy.json` | Sin `testing_window`, sin `escalation_contacts`, sin `DeconflictionPlan` |
| `SwarmOrchestrator` | TokenBudget, roles (Scout/Exploiter/C2/Reporter) | Sin OPPLAN formal, sin tracking de objetivos, sin loop de reanudación |
| `SandboxDispatcher` | Docker + FluidLocal, sanitiza metacaracteres | Sin tokenización shlex, sin denylist de comandos peligrosos (pkill, nsenter, eval) |
| Observabilidad | `tracing` + OTel + OTLP | Sin ActivityLog JSONL por evento, sin `timeline.jsonl` |
| Loop de Persistencia | No existe | Sin PersistenceOrchestrator (exploit→persist→verify) |
| Skills system | No existe | Sin base de conocimiento táctico por técnica MITRE |

---

## Fase 1 — Finding Schema V2 + RoE Formal

**Duración estimada: 3-4 días**
**Archivos afectados: `models/findings.rs`, `core/policy/mod.rs`**

### 1.1 — Enriquecer `Finding` struct

El `Finding` actual ya tiene `cvss_score` y `mitre_attack`. Faltan:
- `cvss_vector: Option<String>` — vector CVSS completo (ej. `CVSS:4.0/AV:N/AC:L/...`)
- `cvss_version: String` — versión CVSS usada (default `"4.0"`)
- `cwe: Vec<String>` — IDs CWE (ej. `["CWE-89"]`)
- `detected: Option<bool>` — si el Blue Team detectó la actividad (Purple Team tracking)
- `detection_notes: String` — qué mecanismos de detección dispararon o fallaron
- `consolidation_urgency: Option<ConsolidationUrgency>` — urgencia: immediate/short-term/long-term
- `evidence_files: Vec<EvidenceFile>` — artefactos con SHA-256 y path relativo

```rust
// models/findings.rs — añadir estos tipos

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsolidationUrgency {
    Immediate,   // 0-7 días
    ShortTerm,   // 30 días
    LongTerm,    // 90+ días
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceFile {
    pub evidence_type: String,  // screenshot, http-request, terminal-log, scan-output
    pub path: String,           // path relativo al workspace
    pub description: String,
    pub sha256: String,         // chain-of-custody
    pub collected_at: chrono::DateTime<chrono::Utc>,
}
```

Campos a añadir en `Finding` (todos opcionales para compatibilidad):
```rust
pub cvss_vector: Option<String>,
pub cvss_version: String,           // default "4.0"
pub cwe: Vec<String>,
pub detected: Option<bool>,
pub detection_notes: String,
pub consolidation_urgency: Option<ConsolidationUrgency>,
pub evidence_files: Vec<EvidenceFile>,
pub objective_id: String,           // OBJ-xxx del OPPLAN
pub agent: String,                  // agente que descubrió el finding
pub iteration: u32,                 // iteración del loop
```

### 1.2 — Serialización a Markdown

Añadir método `to_markdown(&self) -> String` en `Finding` que genere `FIND-001.md` con el formato de Decepticon (compatible con el PersistenceOrchestrator futuro).

### 1.3 — RoE Schema Completo

Extender `core/policy/mod.rs` con los tipos formales de RoE:

```rust
// Nuevos tipos en core/policy/mod.rs

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationContact {
    pub name: String,
    pub role: String,
    pub channel: String,
    pub available: String,  // "24/7", "Mon-Fri 09:00-18:00"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeconflictionPlan {
    pub engagement_name: String,
    pub soc_contact: String,
    pub deconfliction_code: String,
    pub notification_procedure: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoE {
    pub engagement_name: String,
    pub client: String,
    pub start_date: String,
    pub end_date: String,
    pub testing_window: String,         // "Mon-Fri 09:00-18:00 UTC"
    pub in_scope: Vec<ScopeEntry>,
    pub out_of_scope: Vec<ScopeEntry>,
    pub prohibited_actions: Vec<String>,
    pub permitted_actions: Vec<String>,
    pub escalation_contacts: Vec<EscalationContact>,
    pub incident_procedure: String,
    pub authorization_reference: String,
    pub cleanup_required: bool,
    pub deconfliction: Option<DeconflictionPlan>,
}
```

Añadir a `PolicyProvider`:
```rust
fn is_within_testing_window(&self) -> bool;
fn get_roe(&self) -> Option<&RoE>;
```

Añadir a `StaticPolicy`: carga de `workspace/plan/roe.json` y validación de `testing_window` con `chrono`.

**Criterio de éxito:** `cargo build` pasa, todos los findings existentes siguen compilando (campos nuevos son `Option` o tienen `default`).

---

## Fase 2 — OPPLAN: Tracking Formal de Objetivos

**Duración estimada: 4-5 días**
**Archivos nuevos: `core/opplan.rs` | Afectados: `core/mod.rs`, `core/swarm/orchestrator.rs`**

### 2.1 — Tipos OPPLAN

Nuevo archivo `src/core/opplan.rs`:

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ObjectivePhase {
    Recon,
    InitialAccess,
    PostExploit,
    C2,
    Exfiltration,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum OpsecLevel {
    Loud, Standard, Careful, Quiet, Silent,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ObjectiveStatus {
    Pending, InProgress, Completed, Blocked, Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Objective {
    pub id: String,                         // OBJ-001
    pub phase: ObjectivePhase,
    pub title: String,
    pub description: String,
    pub acceptance_criteria: Vec<String>,
    pub priority: u32,
    pub status: ObjectiveStatus,
    pub mitre: Vec<String>,
    pub opsec: OpsecLevel,
    pub opsec_notes: String,
    pub blocked_by: Vec<String>,            // IDs de objetivos dependientes
    pub parent_id: Option<String>,          // Pentesting Task Tree
    pub owner: String,                      // agente asignado
    pub notes: String,
    pub findings_produced: Vec<String>,     // FIND-xxx refs
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OPPLAN {
    pub engagement_name: String,
    pub threat_profile: String,
    pub objectives: Vec<Objective>,
}

impl OPPLAN {
    pub fn load(workspace: &Path) -> Result<Option<Self>>;
    pub fn save(&self, workspace: &Path) -> Result<()>;
    pub fn next_pending(&self, completed_ids: &HashSet<String>) -> Option<&Objective>;
    pub fn update_status(&mut self, id: &str, status: ObjectiveStatus) -> Result<()>;
    // Validación de transiciones: pending→in-progress→completed/blocked
    fn is_valid_transition(from: &ObjectiveStatus, to: &ObjectiveStatus) -> bool;
}
```

### 2.2 — Integrar OPPLAN en SwarmOrchestrator

En `SwarmOrchestrator::run()`:
1. Cargar OPPLAN desde `workspace/plan/opplan.json` si existe.
2. Iterar objetivos en orden de prioridad (respetando `blocked_by`).
3. Actualizar estado del objetivo tras cada iteración.
4. Guardar estado en `workspace/.engagement-state.json` tras cada iteración.

```rust
// Añadir a SwarmOrchestrator
pub workspace: Option<PathBuf>,
pub opplan: Option<Arc<tokio::sync::Mutex<OPPLAN>>>,
```

### 2.3 — EngagementState para reanudación

```rust
// core/opplan.rs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngagementState {
    pub phase: EngagementPhase,
    pub iteration: u32,
    pub max_iterations: u32,
    pub current_objective_id: Option<String>,
    pub objectives_completed: Vec<String>,
    pub objectives_blocked: Vec<String>,
    pub findings_discovered: Vec<String>,
    pub target: String,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub resumed_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl EngagementState {
    pub fn load(workspace: &Path) -> Option<Self>;
    pub fn save(&self, workspace: &Path) -> Result<()>;
    pub fn is_complete(&self) -> bool;
}
```

**Criterio de éxito:** `--autonomous` con un `opplan.json` en el workspace itera los objetivos en orden, actualiza estados y puede reanudarse tras Ctrl-C.

---

## Fase 3 — ActivityLog JSONL

**Duración estimada: 1-2 días**
**Archivo nuevo: `utils/activity_log.rs` | Afectados: `utils/mod.rs`, `core/sink.rs`**

### 3.1 — ActivityLog

```rust
// utils/activity_log.rs

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEvent {
    pub ts: f64,
    pub kind: String,   // tool_call | finding | agent_step | note | objective
    pub actor: String,  // scout | exploiter | c2 | reporter | system
    pub message: String,
    pub target: Option<String>,
    pub data: serde_json::Value,
}

pub struct ActivityLog {
    path: PathBuf,
    // Usa tokio::sync::Mutex<tokio::fs::File> para append async
}

impl ActivityLog {
    pub async fn new(path: PathBuf) -> Result<Self>;
    pub async fn log(&self, kind: &str, actor: &str, message: &str,
                     target: Option<&str>, data: serde_json::Value) -> Result<LogEvent>;
    pub async fn tail(&self, n: usize) -> Result<Vec<LogEvent>>;
}
```

Integrar en el pipeline: cada finding que pasa por `MultiSink` también escribe un evento `kind: "finding"` en el `ActivityLog`.

**Criterio de éxito:** Tras un scan, `workspace/timeline.jsonl` existe y es consumible con `jq '.[] | select(.kind=="finding")'`.

---

## Fase 4 — SafeCommandMiddleware en SandboxDispatcher

**Duración estimada: 1-2 días**
**Archivo afectado: `core/sandbox.rs`**

### 4.1 — Tokenizador de comandos

El `SandboxDispatcher::sanitize_args()` actual bloquea metacaracteres pero no tokeniza comandos completos. Añadir:

```rust
// core/sandbox.rs

const DANGEROUS_COMMANDS: &[(&str, &str)] = &[
    ("pkill",    "Use kill <pid> instead"),
    ("killall",  "Use kill <pid> instead"),
    ("nsenter",  "Container namespace escape blocked"),
    ("eval",     "Run the command directly instead"),
    ("iptables", "Firewall modification blocked — document finding instead"),
    ("ip6tables","Firewall modification blocked"),
    ("nft",      "Firewall modification blocked"),
];

const DANGEROUS_SUBCOMMANDS: &[(&str, &str, &str)] = &[
    ("docker", "exec",    "You are inside the sandbox — run commands directly"),
    ("docker", "run",     "You are inside the sandbox — run commands directly"),
    ("ip",     "route",   "Routing table modification blocked"),
];

const DANGEROUS_TARGETS: &[&str] = &["bash", "tmux", "sh", "zsh"];

/// Tokeniza un comando shell de forma simple (sin dependencias externas).
/// Divide por espacios respetando comillas simples y dobles.
fn tokenize_command(cmd: &str) -> Vec<String>;

/// Verifica si un comando tokenizado es peligroso.
/// Retorna Some(reason) si debe bloquearse, None si es seguro.
pub fn check_command_safety(cmd: &str) -> Option<String>;
```

Integrar `check_command_safety` en `execute_tool_streamed` antes de `sanitize_args`.

**Criterio de éxito:** `pkill bash` → bloqueado con mensaje. `echo 'pkill bash'` → permitido.

---

## Fase 5 — PersistenceOrchestrator (Exploit→Persist→VerifyAccess)

**Duración estimada: 5-7 días**
**Archivo nuevo: `core/vaccine.rs` | Afectados: `core/mod.rs`, `core/engine/mod.rs`**

### 5.1 — PersistencePlan

```rust
// core/vaccine.rs

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DefenseActionType {
    BlockPort, DisableService, RevokeCredential,
    UpdateConfig, KillProcess, AddFirewallRule,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefenseRecommendation {
    pub action_type: DefenseActionType,
    pub target: String,
    pub priority: u32,
    pub rationale: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistencePlan {
    pub finding_ref: String,        // FIND-001
    pub finding_title: String,
    pub severity: String,
    pub attack_vector: String,
    pub affected_assets: Vec<String>,
    pub recommended_actions: Vec<DefenseRecommendation>,
    pub evidence_summary: String,
}
```

### 5.2 — PersistenceOrchestrator

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum VaccineMode { Batch, Immediate }

pub struct PersistenceOrchestrator {
    workspace: PathBuf,
    mode: VaccineMode,
    router: Arc<TieredAIRouter>,
}

impl VaccineOrchestrator {
    pub async fn run(&self, findings: &[String]) -> Result<VaccineState>;

    // Fases internas:
    async fn generate_plan(&self, finding_ref: &str) -> Result<Option<PersistencePlan>>;
    async fn deploy_persistence(&self, plan: &PersistencePlan) -> Result<()>;
    async fn verify_access(&self, finding_ref: &str) -> Result<ReAttackOutcome>;
    fn infer_recommendations(&self, attack_vector: &str, severity: &str) -> Vec<DefenseRecommendation>;
    fn parse_finding_markdown(&self, content: &str) -> (String, String, String, Vec<String>, String);
}
```

El `VaccineOrchestrator` lee los `FIND-*.md` del workspace (generados por `Finding::to_markdown()`), genera un `DefenseBrief`, lo escribe en `workspace/defense-brief.json`, invoca el agente defensor vía el router AI, y lee el resultado de `workspace/verification-FIND-001.json`.

### 5.3 — Integración en el engine

Añadir flag `--persist` al CLI (`main.rs`) que activa el modo de post-explotación tras el scan ofensivo.

**Criterio de éxito:** Con `--persist`, tras encontrar findings, el sistema genera `persistence-plan.json` y `verification-FIND-*.json` en el workspace.

---

## Fase 6 — Skills System

**Duración estimada: 2-3 días**
**Directorio nuevo: `skills/` | Archivo nuevo: `core/skills.rs`**

### 6.1 — Estructura de skills

```
skills/
├── recon/
│   ├── passive-recon/SKILL.md
│   ├── active-recon/SKILL.md
│   └── osint/SKILL.md
├── exploitation/
│   ├── web/SKILL.md
│   └── ad/SKILL.md
├── post-exploit/
│   ├── lateral-movement/SKILL.md
│   └── privilege-escalation/SKILL.md
└── shared/
    ├── opsec/SKILL.md
    └── finding-protocol/SKILL.md
```

### 6.2 — SkillsLoader

```rust
// core/skills.rs

pub struct SkillsLoader {
    skills_dir: PathBuf,
    cache: DashMap<String, String>,  // phase → content
}

impl SkillsLoader {
    pub fn new(skills_dir: PathBuf) -> Self;
    pub fn load_for_phase(&self, phase: &ObjectivePhase) -> Option<String>;
    pub fn load_for_agent(&self, agent_role: &AgentRole) -> Option<String>;
}
```

Integrar en `SwarmOrchestrator`: inyectar el skill relevante en el contexto del agente antes de cada iteración.

**Criterio de éxito:** El agente Scout recibe el contenido de `skills/recon/active-recon/SKILL.md` en su contexto.

---

## Resumen del Roadmap

```
Semana 1
├── Fase 1: Finding V2 + RoE Formal          [3-4 días]
│   ├── EvidenceFile + RemediationPriority
│   ├── Finding::to_markdown()
│   └── RoE struct + testing_window check

Semana 2
├── Fase 2: OPPLAN                            [4-5 días]
│   ├── Objective + OPPLAN types
│   ├── EngagementState (save/load/resume)
│   └── Integración en SwarmOrchestrator

Semana 3
├── Fase 3: ActivityLog JSONL                 [1-2 días]
├── Fase 4: SafeCommandMiddleware             [1-2 días]
└── Buffer / testing

Semana 4-5
└── Fase 5: VaccineOrchestrator              [5-7 días]
    ├── DefenseBrief + tipos
    ├── VaccineOrchestrator::run()
    └── Flag --vaccine en CLI

Semana 6
└── Fase 6: Skills System                    [2-3 días]
    ├── Directorio skills/
    └── SkillsLoader + integración
```

---

## Verificación del Análisis Previo

El análisis del agente anterior era correcto en los puntos estratégicos pero impreciso en algunos detalles técnicos:

| Afirmación del análisis previo | Verificación real |
|---|---|
| "No genera documentos de cumplimiento (RoE) automáticamente" | ✅ Correcto. `StaticPolicy` carga `policy.json` pero no tiene RoE formal |
| "Dificultad para interactuar con herramientas interactivas" | ✅ Correcto. `SandboxDispatcher` usa `Child` con pipes, no PTY |
| "Falta de Formalidad: No genera OPPLAN" | ✅ Correcto. `SwarmOrchestrator` no tiene tracking de objetivos |
| "Implementar Tmux-Bridge en Rust" | ⚠️ Parcialmente correcto. El sandbox ya usa Docker; un PTY nativo es más apropiado que tmux |
| "Finding ya tiene cvss_score y mitre_attack" | ✅ Verificado en `models/findings.rs` — ya existen, faltan los campos adicionales |
| "PolicyProvider ya tiene PSL con addr crate" | ✅ Verificado — `StaticPolicy` ya usa `addr::parse_domain_name` |
| "SafeCommandMiddleware: bloqueo de metacaracteres existe" | ✅ Verificado en `sanitize_args()` — pero sin tokenización shlex ni denylist de binarios |
| "Sin ActivityLog JSONL" | ✅ Correcto. Solo hay `tracing` + OTel, sin log por evento en JSONL |

**Conclusión de verificación:** El análisis previo era estratégicamente sólido. Este roadmap lo convierte en tareas concretas con los archivos exactos a modificar, basado en el código real leído.

---

*Roadmap generado para OsintUltimate V14.x — Implementación de capacidades Decepticon en Rust nativo.*
