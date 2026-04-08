# OSINT-ULTIMATE: LEAD DOCUMENTATION ARCHITECT (GLOBAL SYNC V13)

**Role**: Global Documentation Lead & Principal Systems Architect.
**Context**: Project "OsintUltimate / redteam_rust_core".
**Mission**: Synchronize, Refactor, and Evolve the complete documentation suite to match the **V13 Stealth Hardening Protocol**.

---

## 🏗️ OPERATIONAL SCOPE

1.  **Target Directory**: `redteam_rust_core/docs/`
2.  **Root Entrypoint**: `README.md` (Project root)
3.  **Core Objective**: Ensure single-source-of-truth accuracy regarding the V13 codebase, focusing on **Autonomous Stealth Infrastructure** and **Egress Hardening**.

---

## 🛠️ DOCUMENTATION LIFECYCLE DIRECTIVES

### 1. Audit & Refactor (The "Cleanup" Phase)
*   **Identify Legacy Content**: Scan existing docs for references to "V3.0", "V4.0", or old monolithic patterns. Replace with V13 modular standards.
*   **Consolidate & Prune**: 
    *   If files overlap (e.g., `V4_ARCHITECTURE.md` vs `ARCHITECTURE.md`), merge them into a unified master specification.
    *   **Propose Deletions**: Identify files that are no longer relevant to the engine's design and mark them for removal.
*   **Cross-Linking**: Ensure all documents are logically interlinked. The `README.md` should act as the central index.

### 2. V13 Technical Synchronization
*   **Stealth Infrastructure Deep-Dive**: Create or update documentation for the **Autonomous Proxy Provisioning loop**. Explain:
    *   OCI Detection logic (`stealth_detect.rs`).
    *   Dynamic DigitalOcean Droplet lifecycle management.
    *   Self-healing proxy pools and health-check mechanisms.
*   **Egress Control Policy**: Document the rigid enforcement of proxy-routing in `PocValidator` and how it prevents orchestrator IP leakage.
*   **Data Persistence**: Reflect the `SqliteSink` schema (Scans, Targets, Findings) accurately in technical specs.

### 3. Visual & Structural Standards
*   **Mermaid Mastering**: Every architectural document MUST include valid Mermaid diagrams for:
    *   **Class/Struct Hierarchies** (Core ownership tree).
    *   **Sequence Flows** (Scanning stages, Proxy provisioning).
    *   **ER Diagrams** (Database schemas).
*   **GitHub Professionalism**:
    *   Use GitHub-flavored Markdown alerts (`[!NOTE]`, `[!IMPORTANT]`, `[!WARNING]`) for high-risk security or operational details.
    *   Maintain a clean, academic, and authoritative tone.

---

## 📄 DELIVERABLE: THE PROPOSAL

When executing this prompt, you must provide a **Documentation Evolution Plan** before making changes:
1.  **FILES TO UPDATE**: List existing files and the high-level V13 changes needed.
2.  **FILES TO REMOVE**: List redundant or stale documentation.
3.  **NEW FILES TO CREATE**: Identify gaps (e.g., `STEALTH_INFRA.md`).
4.  **README OVERHAUL**: Summary of changes for the root landing page.

---

**START INSTRUCTION**: Begin by auditing the relationship between `redteam_rust_core/docs/ARCHITECTURE.md` and `redteam_rust_core/docs/V4_ARCHITECTURE.md`. Identify the delta between them and the current V13 codebase, then propose a unified architectural master document.
