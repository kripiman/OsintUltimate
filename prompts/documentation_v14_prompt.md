# OSINT-ULTIMATE: SOVEREIGN SYSTEMS DOCUMENTARIAN (COMPREHENSIVE SYNC)

**Role**: Chief Architect & Principal Systems Documentarian.
**Paradigm**: Full-Spectrum Sovereignty & Ground-Truth Documentation.
**Goal**: Update ALL system documentation to reflect the true state of the OSINT-Ultimate ecosystem, meticulously mapping the implementation against standard Pentesting / Red Team / Bug Bounty phases.

> [!NOTE]
> **Subdivided Execution**: Do not attempt to complete the entire documentation overhaul in a single response. Subdivide the work into manageable phases across multiple interactions to ensure extreme detail and accuracy.

---

## 🛑 STRICT DIRECTIVES

1. **Code Dictates Documentation**: The Rust implementation in `src/` is the infallible single source of truth. Do not invent features or describe theoretical capabilities not currently present in the code.
2. **Phase Mappings**: Every piece of infrastructure must be mapped precisely to the standard offensive lifecycle (Passive Recon, Discovery, Active Scanning, Verification, Exploitation, Post-Exploitation).
3. **Mermaid Diagrams**: EVERY phase analyzed must include highly detailed Mermaid diagrams (e.g., `sequenceDiagram`, `flowchart LR`, `stateDiagram`) illustrating data flow, tool execution, egress boundaries, and proxy usage.

---

## 🛡️ THE RED TEAM / BUG BOUNTY LIFECYCLE (PHASES)

Analyze and document the system according to these explicit phases:

### PHASE 0: PRE-ENGAGEMENT & PASSIVE OSINT (Layer 0)
* **Goal**: Non-attributable data collection. Zero packets touching the target infrastructure.
* **Components**: `OsintScanner`, `WaybackScanner`, `TruffleHogScanner`.
* **Diagram Requirement**: Illustrate how OSINT plugins gather data strictly through `ProxyManager::get_client_fail_closed()` to ensure OPSEC against third-party APIs (crt.sh, GitHub, out-of-band sources).

### PHASE 1: DISCOVERY & ENUMERATION (Layer 1)
* **Goal**: Mapping the external attack surface via light probing and asset correlation.
* **Components**: `DnsxScanner`, `HttpxScanner`, `WhatWebScanner`.
* **Diagram Requirement**: Show the connection flow including User-Agent rotation, payload formatting, and strict proxy routing constraints via proxychains/fail-closed clients.

### PHASE 2: ACTIVE SCANNING & VULNERABILITY ANALYSIS (Layer 2)
* **Goal**: Deep scanning, fuzzing, and heavy vulnerability identification.
* **Components**: `NmapScanner`, `NucleiScanner`, `WebFuzzer`.
* **Diagram Requirement**: Flowchart detailing `ScanLayerPolicy`, stealth execution logic within `StealthExecutor::spawn()`, and resource constraints.

### PHASE 3: POC VERIFICATION & SOVEREIGN GATE (Layer 3)
* **Goal**: Validating critical findings safely and halting autonomy for complex exploits.
* **Components**: `PocValidator`, `ApprovalGate`.
* **Diagram Requirement**: Sequence diagram of the "Sovereign Handover" process where high-complexity exploits (RiskLevel >= 70) halt the autonomous loop and wait for explicit human operator verification/payload provision.

### PHASE 4: INITIAL ACCESS & EXPLOITATION (Layer 4)
* **Goal**: Striking the target and achieving validated code execution.
* **Components**: `SqlMapScanner`, `ImpacketScanner`, `CommixScanner`, `RemoteExecutor`.
* **Diagram Requirement**: Diagram detailing how validated payloads are safely delivered and executed through the `StealthExecutor`'s remote dispatch pipelines.

### PHASE 5: POST-EXPLOITATION, C2 & PIVOTING (Layer 5)
* **Goal**: Establishing persistence, managing Command and Control, AD mapping, and lateral movement.
* **Components**: `SliverScanner`, `HavocScanner`, `LigoloScanner`, `BloodHoundScanner`.
* **Diagram Requirement**: Complex flowchart showing the One-Time-Token (OTT) `PayloadServer` staging, remote delivery to managed proxy exits, TeamServer REST API session verification, and autonomous AD graph ingest (`AdIngestor` -> `CorrelationEngine`).

---

## 🛠️ CORE INFRASTRUCTURE INTEGRATION

During the phase documentation, explicitly detail how these core systems underpin operations:
* **StealthExecutor & ProxyManager**: The failsafe boundary. How `wrap_command()` prevents unproxied execution.
* **SwarmOrchestrator**: How token budgets (`TokenBudget`), priority mechanisms, and the context compressor (`ContextCompressor`) guide autonomous agent assignment.
* **CorrelationEngine / AttackGraph**: How ingested edges and nodes interact to provide DFS-based attack paths (e.g., "Path to Domain Admin").

---

**START INSTRUCTION**: Begin the documentation process by creating the comprehensive System Overview and fully detailing **PHASE 0 (Pre-engagement & Passive OSINT)**. 
1. Review the related code in `src/`.
2. Generate the detailed description, technical specifications, and corresponding Mermaid diagrams for Phase 0 based *strictly* on current code logic.
3. Pause, summarize your completion of Phase 0, and wait for my instruction to continue to the next phase.
