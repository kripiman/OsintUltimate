# 🧠 SOVEREIGN AI ARCHITECTURE: OsintUltimate V14.1

This document provides a deep technical breakdown of the autonomous reasoning engine driving the `redteam_rust_core` ecosystem. It outlines the tiered communication model, context compression strategies, and token optimization methodologies that enable military-grade, cost-efficient offensive operations.

---

## 🏛️ 1. ARCHITECTURAL OVERVIEW
The AI system functions as a **Swarm Orchestrator**, utilizing a multi-agent logic (Scout, Exploiter, C2-Operator) to navigate the offensive lifecycle. The architecture follows a **Decentralized Reasoning** approach where the "Brain" is not a single model, but a **Tiered Router** that dynamically selects the optimal LLM based on task complexity, risk level, and egress constraints.

### 🐝 Multi-Agent Role Definition
- **Planner (Tier-1/2)**: Processes high-level telemetry to assign roles to specific agents.
- **Scout (Tier-0/1)**: Deepens infrastructure reconnaissance and technology fingerprinting.
- **Exploiter (Tier-1/2)**: Orchestrates active vulnerability validation and PoC execution.
- **C2-Operator (Tier-1)**: Manages post-exploitation delivery and session maintenance.
- **Ghost-Reporter (Tier-0)**: Conducts low-noise archiving and passive auditing.

---

## 📡 2. COMMUNICATIONS: THE TIERED ROUTER
The system uses the `TieredAIRouter` to manage multiple LLM providers (Ollama, Gemini, OpenAI, Claude). Communication is routed through three distinct levels to balance intelligence and cost.

### 📶 Routing Tiers
| Tier | Model Examples | Trigger Criteria | Cost Profile |
|:--- |:--- |:--- |:--- |
| **Tier 0 (Local)** | Qwen 2.5, Llama 3.1 | Passive Recon, Code Auditing, Initial Triage | $0.00 (Offline) |
| **Tier 1 (Mid)** | Gemini Flash, GPT-4o-mini| Vulnerability analysis, WAF Evasion planning | Ultra-Low Cost |
| **Tier 2 (Premium)**| Gemini Pro, GPT-4o | 0-day validation, High-value AD paths, Critical BREACH| Professional Tier |

---

## 🗜️ 3. CONTEXT MANAGEMENT & COMPRESSION
To maintain high performance and minimize "token bleed," the system implements aggressive compression via the `ContextCompressor`.

### 📉 Compression Methodologies
1. **Strategic Truncation**: Response bodies and source code snippets are aggressively truncated (e.g., to 512 chars) unless the agent's posture requires deep inspection.
2. **Header Stripping**: HTTP headers are scrubbed of noise (Cookie, Date, Content-Type) while preserving critical security markers (`Server`, `X-Powered-By`, `CSP`).
3. **Tech-Stack Normalization**: Finding data is boiled down to a flat "Tech Inventory" (e.g., `["nginx", "php", "laravel"]`) to save context space during planning.
4. **Swarm Context Minification**: Planner agents receive only high-level IDs and Severity scores, stripping raw evidence to allow for higher concurrency in the agent swarm.

---

## 🦖 4. THE CAVEMAN PROTOCOL (TOKEN OPTIMIZATION V14.1)
To achieve production-grade cost-efficiency, the system implements the **Caveman Protocol**, which drastically reduces token consumption through linguistic density.

### 🉐 Wenyan-Ultra (Classical Chinese Compression)
- **High-Tier Default**: All Tier-2 (Premium) agents communicate internally using **文言文 (Classical Chinese)**.
- **Compression Ratio**: Achieves ~75-90% character reduction depending on the technical depth.
- **Technical Integrity**: The AI is instructed to maintain 100% technical accuracy while using minimal character footprints.

### 📶 Intensity Levels
- **Lite**: No filler words, full sentences.
- **Full**: Fragmented English, dropped articles, telegraphic.
- **Wenyan-Ultra**: Maximum compression via classical literary Chinese.

### 🇪🇸 Human Language Pivot
A critical "Safety Override" logic. When the AI requires human intervention (via `ApprovalGate` or when generating a "Sovereign Handover" script), it **automatically pivots to English or Spanish**. This ensures that the human operator receives a clear, actionable mission briefing without linguistic barriers.

---

## 🛡️ 5. OPSEC & SECRET SCRUBBING
Before any data traverses a Tier 1 or Tier 2 egress path (Remote LLMs), it passes through a **Zero-Trust Scrubber**.

### 🧼 SecretRedaction Engine
The `SecretScrubber` uses a high-precision regex catalog (TruffleHog/Gitleaks compliant) to redact:
- **Cloud Tokens**: AWS, GitHub, Slack, Stripe, HuggingFace.
- **Database Strings**: Passwords and hostnames are masked.
- **Topology markers**: Internal RFC 1918 IPs and Localhost references.
- **PII**: Emails and Auth Headers are placeholder-replaced.

> [!IMPORTANT]
> **Ghost Posture Protection**: Internal topology is ALWAYS redacted for Remote Tiers but preserved for Local Tiers to ensure the AI has situational awareness without leaking target infrastructure to LLM providers.

---

## ⚡ 5. OPERATIONAL POSTURES (STATE MACHINE)
The AI adjusts its decision-making logic based on the `AdaptiveContext` and the current engagement **Posture**:

1. **👻 GHOST (Passive)**: Default starting state. AI prioritizes low-noise, passive collection. No active exploitation allowed.
2. **💥 STRIKE (Active)**: Triggered during vulnerability validation. AI shifts to high-precision, invasive scanning patterns.
3. **🔱 BREACH (Persistence)**: Post-exploitation state. AI focuses on lateral movement, AD ingestion, and C2 maintenance.

6. **🔱 BREACH (Persistence)**: Post-exploitation state. AI focuses on lateral movement, AD ingestion, and C2 maintenance.

---

## 💸 7. TOKENOMICS: THE BUDGET SYSTEM
The `TokenBudget` and `TokenGuard` structures provide a race-condition-safe methodology for managing autonomous costs.

### 📈 Admission Control
- **Priority Throttling**: Low-priority tasks (Scouting) are throttled when the budget reaches 75%.
- **Planner Reservation**: High-priority tasks (Planning) have guaranteed access to 100% of the budget.
- **RAII-TokenGuards**: Tokens are "reserved" before a call and "released" or "committed" after. If an agent task panics, the `TokenGuard` (via `Drop`) automatically refunds the reserved tokens back to the pool, preventing systemic "Token Death."

---

## 🚀 7. EXPLOITATION LOGIC
During the **STRIKE** posture, the AI interfaces with the `PocValidator`.
1. **Risk Scoring**: AI calculates a `risk_score` (1-10). If score $\geq$ 7, it triggers the `ApprovalGate`.
2. **WAF Awareness**: `AdaptiveContext` tracks block counts and evasion stages (Header $\rightarrow$ TLS $\rightarrow$ AI-Evasion), allowing the model to refine its payload between attempts.
3. **Verification**: AI-driven analysis of the validation output determines if a finding is "Verified," which then signals the orchestrator to transition to a **BREACH** posture.

---

## 🏛️ 9. INTEGRITY & FAIL-CLOSED SOVEREIGNTY
The system is strictly **Fail-Closed**. If the `ProxyManager` or high-tier AI egress paths are compromised or unavailable, the autonomous pipeline halts immediately to prevent unproxied "Ghost Leaks."

---
*Last Updated: 2026-04-15*
*Architecture Version: V14.1-SOVEREIGN-CAVEMAN*
