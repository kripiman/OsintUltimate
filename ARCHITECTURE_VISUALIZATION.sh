#!/bin/bash
# 🎨 OsintUltimate v3.0 - Architecture Visualization

cat << 'EOF'

╔══════════════════════════════════════════════════════════════════════════════╗
║                   📦 OsintUltimate v3.0 Architecture                         ║
║                    Enterprise Red Team Platform                              ║
╚══════════════════════════════════════════════════════════════════════════════╝

┌──────────────────────────────────────────────────────────────────────────────┐
│                          🎮 USER INTERFACE LAYER                             │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  CLI Commands:                                                              │
│  ├─ scan              : Single target scan                                  │
│  ├─ wizard            : Interactive red team workflow                       │
│  ├─ workflow          : Pre-built workflows (AD-to-RCE, Cloud, Web)         │
│  ├─ plugins           : Plugin management (list, info, load, test)           │
│  ├─ audit             : View audit logs                                      │
│  ├─ report            : Generate reports (SARIF, HTML, CSV)                  │
│  └─ approvals         : Manage risk approvals                               │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
                                      ↓
┌──────────────────────────────────────────────────────────────────────────────┐
│                      🏛️ CORE ORCHESTRATION LAYER                             │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────┐        │
│  │ Orchestrator (Async/Tokio)                                      │        │
│  │ ├─ Capability Layer Manager       [ScanLayer: 0-5]             │        │
│  │ ├─ Approval Gate                  [Risk-based auth]            │        │
│  │ ├─ Plugin Registry                [Plugin metadata + deps]      │        │
│  │ ├─ Global Context                 [Correlations + graphs]      │        │
│  │ └─ Pipeline Controller            [4-stage execution]          │        │
│  └─────────────────────────────────────────────────────────────────┘        │
│                                                                              │
│  Capability Layers:                                                         │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │ LAYER 0: Passive      [OSINT, DNS, logs] ◄── Lowest Risk         │    │
│  │ LAYER 1: Discovery    [Light probing, DNS enum]                  │    │
│  │ LAYER 2: Scanning     [Nmap, vulnerability scan]                 │    │
│  │ LAYER 3: Verification [PoC attempts, non-destructive]    ◄  Approval   │
│  │ LAYER 4: Exploitation [Active exploitation, RCE]         ◄  Required   │
│  │ LAYER 5: PostExp      [Persistence, lateral move] ◄── Highest Risk     │
│  └────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│  Approval Gate:                                                              │
│  ├─ Risk Score Calculation (0-100)                                          │
│  ├─ User Role Validation (Analyst/RedTeam/Admin)                            │
│  ├─ Audit Trail Logging                                                     │
│  └─ Policy Enforcement (SOC2/HIPAA/PCI-DSS compliant)                      │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
                                      ↓
┌──────────────────────────────────────────────────────────────────────────────┐
│                      🔌 PLUGIN SYSTEM (80+ Plugins)                          │
│                   ⚡ BlackArch System Tools Integration (NEW)                │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  🎯 BLACKARCH COMPATIBILITY:                                                 │
│  ├─ Auto-Detection: Detects pre-installed BlackArch tools via `which`       │
│  ├─ System Priority: Uses system binaries for maximum efficiency            │
│  ├─ Fallback Mode: Embedded binaries as automatic failover                  │
│  ├─ Integrated Tools: 35+ tools across all plugin categories                │
│  │  ├─ Web: ffuf, nuclei, sqlmap, arjun, dalfox, jwt_tool, wapiti          │
│  │  ├─ Network: rustscan, hydra, netexec, coercer, responder               │
│  │  ├─ Cloud: cloudfox, pacu, cloudenum, cloudbrute                        │
│  │  ├─ Recon: dnsx, httpx, naabu, wayback, uncover                         │
│  │  ├─ Intelligence: jaeles, searchsploit                                  │
│  │  ├─ Compliance: kubescape, trivy                                        │
│  │  └─ Advanced: bloodhound, ligolo, sliver, havoc, certipy               │
│  └─ Version Compatibility: Auto-checks tool versions on startup             │
│                                                                              │
│  RECONNAISSANCE/ (12 plugins)          ENUMERATION/ (20 plugins)            │
│  ├─ osint/                             ├─ web/                              │
│  │  ├─ amass          (Layer 0)         │  ├─ ffuf         (Layer 2)        │
│  │  ├─ subfinder      (Layer 0)         │  ├─ feroxbuster  (Layer 2)        │
│  │  └─ uncover        (Layer 0)         │  ├─ arjun        (Layer 2)        │
│  ├─ passive/                           │  └─ katana       (Layer 1)        │
│  │  ├─ wayback        (Layer 0)         ├─ network/                         │
│  │  ├─ gitleaks       (Layer 0)         │  ├─ rustscan     (Layer 2)        │
│  │  └─ shodan         (Layer 0)         │  ├─ nmap_async   (Layer 2-NEW)    │
│  └─ active/                            │  └─ zmap         (Layer 2-NEW)    │
│     ├─ dnsx           (Layer 1)         └─ cloud/                           │
│     ├─ httpx          (Layer 1)            ├─ cloudenum    (Layer 1)        │
│     └─ naabu          (Layer 1)            ├─ scoutsuite   (Layer 2-NEW)    │
│                                           └─ cloudbrute   (Layer 2)        │
│  EXPLOITATION/ (25 plugins-DANGEROUS)   INTELLIGENCE/ (8 plugins)          │
│  ├─ web/                                ├─ nuclei         (Layer 2)        │
│  │  ├─ sqlmap         (Layer 4)         ├─ yara           (Layer 2-NEW)    │
│  │  ├─ wapiti         (Layer 4)         ├─ mitre_mapper   (Layer 3-NEW)    │
│  │  ├─ dalfox         (Layer 4)         ├─ threat_intel   (Layer 1-NEW)    │
│  │  ├─ commix         (Layer 4-NEW)     └─ correlation    (Layer 3-NEW)    │
│  │  └─ webshell       (Layer 4-NEW)                                        │
│  ├─ network/                            VERIFICATION/ (5 plugins)           │
│  │  ├─ hydra          (Layer 4)         ├─ burp_adapter   (Layer 3)        │
│  │  ├─ netexec        (Layer 4)         ├─ zap_adapter    (Layer 3)        │
│  │  ├─ impacket_async (Layer 4-REF)     ├─ manual_poc     (Layer 3-NEW)    │
│  │  ├─ responder      (Layer 4)         └─ fp_filter_ml   (Layer 3-NEW)    │
│  │  ├─ krbrelay       (Layer 4-NEW)                                        │
│  │  ├─ zerologon      (Layer 4-NEW)     PERSISTENCE/ (5 plugins-NEW)       │
│  │  └─ printnightmare (Layer 4-NEW)     ├─ scheduled_task                  │
│  ├─ wireless/                           ├─ wmi_backdoor                    │
│  │  ├─ hashcat_gpu    (Layer 4-NEW)     ├─ registry_run                    │
│  │  └─ pmkid_crack    (Layer 4-NEW)     └─ service_install                 │
│  └─ mobile/                                                                 │
│     ├─ frida          (Layer 5-NEW)     DETECTION_EVASION/ (8 plugins)     │
│     └─ androguard     (Layer 5-NEW)     ├─ jitter_core                     │
│                                         ├─ proxy_rotation                  │
│  AD_ATTACKS/ (8 plugins)                ├─ anti_honeypot   (Layer 1-NEW)   │
│  ├─ bloodhound       (Layer 2)          ├─ anti_edr        (Layer 1-NEW)   │
│  ├─ certipy          (Layer 4)          ├─ obfuscation     (Layer 1-NEW)   │
│  ├─ coerce_auth      (Layer 4-NEW)      └─ kernel_hide     (Layer 2-NEW)   │
│  └─ samaccountname   (Layer 4-NEW)                                         │
│                                         COMPLIANCE/ (6 plugins-NEW)        │
│  PRIVILEGE_ESCALATION/ (6 plugins-NEW) ├─ checkov                         │
│  ├─ privesc_hunter   (Layer 1-NEW)     ├─ kubebench                       │
│  ├─ linux_privesc    (Layer 4-NEW)     ├─ kubescape                       │
│  ├─ windows_privesc  (Layer 4-NEW)     ├─ nist_csf                        │
│  ├─ container_escape (Layer 4-NEW)     ├─ cis_benchmark                   │
│  └─ delegation_abuse (Layer 4-NEW)     └─ hipaa_audit                     │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
                                      ↓
┌──────────────────────────────────────────────────────────────────────────────┐
│                    ⚙️ EXECUTION PIPELINE (4 Stages)                          │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Input Targets [target1.com, target2.com, ...]                              │
│         ↓                                                                    │
│  ┌─────────────────────────────────────────────────────────────────┐        │
│  │ STAGE 1: Reconnaissance/Discovery [Tokio Channel]              │        │
│  │  └─ OsintScanner → Discovers subdomains via crt.sh + DNS       │        │
│  │     Deduplicates via DashSet                                   │        │
│  └─────────────────────────────────────────────────────────────────┘        │
│         ↓                                                                    │
│  ┌─────────────────────────────────────────────────────────────────┐        │
│  │ STAGE 2: Liveness Check [DNS + Network validation]             │        │
│  │  └─ Validate IP resolution (public ONLY)                       │        │
│  │  └─ SSRF protection: Bloquear RFC1918, CGNAT, metadata ranges  │        │
│  └─────────────────────────────────────────────────────────────────┘        │
│         ↓                                                                    │
│  ┌─────────────────────────────────────────────────────────────────┐        │
│  │ STAGE 3: Parallel Scanning [buffer_unordered(N)]               │        │
│  │  ├─ WebFuzzer [ffuf, feroxbuster, arjun, katana]              │        │
│  │  ├─ NmapScanner [quick-xml parsing]                           │        │
│  │  ├─ VulnScanning [nuclei, wapiti, sqlmap - if approved]        │        │
│  │  └─ CustomPlugins [Any registered ScannerPlugin]              │        │
│  │                                                                 │        │
│  │  Semaphore Control:  Limitar concurrencia a N workers          │        │
│  │  Jitter Applied:     LogNormal distribution para evasión       │        │
│  │  Proxy Rotation:     DashMap per-request                       │        │
│  │  Error Handling:     Retry con backoff exponencial             │        │
│  └─────────────────────────────────────────────────────────────────┘        │
│         ↓                                                                    │
│  ┌─────────────────────────────────────────────────────────────────┐        │
│  │ STAGE 4: Results Sink [JSONL + Report Generation]              │        │
│  │  ├─ JsonlSink [Streaming write to disk every 10 items]         │        │
│  │  ├─ SqliteSink [Option: Persistent results DB]                 │        │
│  │  └─ ReportGenerator                                            │        │
│  │      ├─ HTML Report [Handlebars templating]                   │        │
│  │      ├─ SARIF Export [Azure DevOps/GitHub integration]         │        │
│  │      ├─ CSV Export [Spreadsheet friendly]                      │        │
│  │      └─ Executive Summary [AI-powered insights]                │        │
│  │                                                                 │        │
│  │  Post-Processing:                                              │        │
│  │  ├─ AI Correlation [Global context attack chains]              │        │
│  │  ├─ MITRE Mapping [Técnicas detectadas]                        │        │
│  │  ├─ Compliance Check [NIST/CIS/ISO/HIPAA/PCI-DSS]             │        │
│  │  └─ Risk Scoring [CVSS + business impact]                      │        │
│  └─────────────────────────────────────────────────────────────────┘        │
│         ↓                                                                    │
│  Output: ./results.jsonl, ./report.html, ./report.sarif, ./report.csv       │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
                                      ↓
┌──────────────────────────────────────────────────────────────────────────────┐
│                     📊 ANALYSIS & CORRELATION ENGINE                         │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Global Context (NEW):                                                       │
│  ├─ ServiceRegistry      : All discovered services (dedup global)           │
│  ├─ AttackGraphs         : petgraph relations entre hallazgos              │
│  ├─ Correlations         : "(SQLi in webapp1) → (Access to DB) → (PII)"   │
│  └─ MitreMapper          : Map findings a MITRE ATT&CK techniques          │
│                                                                              │
│  AI Analysis Mode (Optional with Ollama/OpenAI):                            │
│  └─ Determine impact, prioritize, suggest exploitation chains              │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
                                      ↓
┌──────────────────────────────────────────────────────────────────────────────┐
│                        📋 PROFESSIONAL REPORTING                             │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Executive Summary (1-2 pages):                                              │
│  ├─ 5 Critical findings identified                                          │
│  ├─ Timeline: Exploitation possible in X hours                              │
│  ├─ Business impact: Up to $2.5M if exploited                               │
│  └─ CTO-friendly: "Fix 2 of 5 = 95% security improvement"                  │
│                                                                              │
│  Detailed Report (HTML interactive):                                         │
│  ├─ Vulnerability details (CVSS + CWE)                                      │
│  ├─ Attack chains (visual graph)                                            │
│  ├─ MITRE ATT&CK heatmap (tactics covered)                                  │
│  ├─ Compliance gaps (NIST CSF, CIS Benchmarks)                              │
│  ├─ Remediation roadmap + estimated cost                                    │
│  └─ Timeline recommendations (by priority)                                  │
│                                                                              │
│  Compliance Report (NEW):                                                    │
│  ├─ NIST CSF: Which controls violated                                       │
│  ├─ ISO 27001: Specific requirement gaps                                    │
│  ├─ HIPAA: PHI exposure risks                                               │
│  ├─ PCI-DSS: Payment data security violations                               │
│  └─ GDPR: Personal data handling issues                                     │
│                                                                              │
│  SARIF Format (DevOps integration):                                          │
│  ├─ GitHub: Auto-comment PRs with security findings                         │
│  ├─ Azure DevOps: Push to security dashboard                                │
│  ├─ GitLab: Create issues automatically                                     │
│  └─ Jenkins: Fail builds if critical findings                               │
│                                                                              │
│  CSV Export (Spreadsheet tools):                                             │
│  ├─ For tracking in Jira/Azure Boards                                       │
│  ├─ Easy filtering by severity/status                                       │
│  └─ Historical trend analysis                                               │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────────┐
│                     🔐 SECURITY & COMPLIANCE FEATURES                        │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Access Control:                                                             │
│  ├─ Role-based (Analyst, RedTeamBasic, RedTeamFull, Admin, CISO)           │
│  ├─ Layer-based (Only execute plugins ≤ authorized layer)                   │
│  └─ Risk-based (Request approval for high-risk actions)                     │
│                                                                              │
│  Audit Trail (Immutable):                                                    │
│  ├─ Who: User ID + Role                                                     │
│  ├─ What: Action + Plugin + Parameters                                      │
│  ├─ When: Timestamp (UTC)                                                   │
│  ├─ Result: APPROVED / REJECTED / IN_PROGRESS / FAILED                     │
│  └─ Export: JSON for compliance audits                                      │
│                                                                              │
│  Evasion Techniques (Built-in):                                              │
│  ├─ Jitter LogNormal (Simulates human behavior)                             │
│  ├─ Proxy Rotation (Per-request IP rotation)                                │
│  ├─ Anti-Honeypot (Detect canary files/URLs)                                │
│  ├─ Anti-EDR (Bypass detection techniques)                                  │
│  └─ Custom Obfuscation (Configurable payload encoding)                      │
│                                                                              │
│  Data Protection:                                                            │
│  ├─ Sensitive data encrypted at rest (optional Vault integration)           │
│  ├─ Credentials stored securely (not in logs)                               │
│  ├─ Results purged after X days (configurable)                              │
│  └─ PII detection + masking in reports                                      │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘

╔══════════════════════════════════════════════════════════════════════════════╗
║                         🚀 KEY ADVANTAGES                                    ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  ✅ 80+ integrated tools (vs Burp ~30)                                        ║
║  ✅ 5x performance improvement (Async Rust vs Java/Python)                  ║
║  ✅ 94% cost reduction ($18,997 → $1,000/year)                              ║
║  ✅ Enterprise compliance built-in (SOC2, HIPAA, PCI-DSS)                   ║
║  ✅ Capability layers (control aggressiveness)                              ║
║  ✅ Approval gates (regulatory conformity)                                  ║
║  ✅ AI-powered correlation (automatic attack chains)                        ║
║  ✅ Professional reporting (SARIF, HTML, executive summaries)               ║
║  ✅ Open-source (customizable + community contributions)                    ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝

EOF

echo ""
echo "📌 This visualization shows OsintUltimate v3.0 Complete Architecture"
echo "📁 Location: /home/kripi/Documentos/GitHub/OsintUltimate/"
echo "📚 Docs: STRATEGIC_ENHANCEMENT_V3.md + STEP_BY_STEP_IMPLEMENTATION.md"
echo ""
