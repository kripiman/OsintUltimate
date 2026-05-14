# Mimikri Core — System Architecture Reference

> Derived from source code (`src/`). Authoritative. Last verified: 2026-05-13 (V15.1 Hardened).

---

## 1. Bootstrap & Configuration Flow

```mermaid
flowchart TD
    A["main.rs: tokio::main"] --> B{"args.len == 1?"}
    B -- yes --> C["menu::show_menu<br/>interactive TUI"]
    B -- no --> D["Args::parse via clap"]
    C & D --> E["init_telemetry<br/>OTEL + JSON logs"]
    E --> F["binary_health_check<br/>P0: bbscope asnmap cdncheck tlsx clairvoyance"]
    F --> G["EngineFactory::detect_infrastructure_limits<br/>UltraLow / LocalPC / Hybrid / Server"]
    G --> H["Config::from_env<br/>70+ env vars, typed Config struct"]
    H --> I["Build EngineConfig<br/>bridge: Config to Engine"]
    I --> J["RedTeamEngine::from_config"]
    J --> K{"--worker flag?"}
    K -- yes --> L["run_worker_mode<br/>NATS + scan_queue polling"]
    K -- no --> M["Normal scan + sink assembly"]
```

**Key invariants:**
- `Config::from_env()` is the single env-var read point. Engine never reads env directly.
- `MIMIKRI_WORKSPACE` controls all output paths. Default: `./workspace`.
- Hardware profiles set auto-concurrency: UltraLow=10, LocalPC=30, Hybrid=60, Server=150.

---

## 2. Target Ingestion Sources

```mermaid
flowchart LR
    subgraph Sources
        T1["--target hostname\nsingle host"]
        T2["--input file.txt\nline-by-line"]
        T3["--apk app.apk\nMobile TargetType"]
        T4["--image alpine:latest\nContainer TargetType"]
        T5["CertStream daemon\nCERTSTREAM_KEYWORDS env\nmonitors CT logs"]
        T6["Dashboard REST API\nMissionRequest → injection_tx mpsc"]
    end
    Sources -->|BoxStream TargetHost| VAL[validate_target\n+ is_ssrf_safe_host_async]
    VAL -->|clean stream| MERGE[futures::stream::select_all]
    MERGE --> Pipeline
```

All targets validated before entering the pipeline. Invalid targets logged and dropped.

---

## 3. Sink Assembly (main.rs)

```mermaid
flowchart TD
    MS[MultiSink\nbroadcasts to all]
    MS --> BS["BountySink\nH1 / Bugcrowd / Intigriti\nsubmits on close()"]
    MS --> NS["NatsSink\n--nats-url\ndecentralized mesh broadcast"]
    MS --> DB["PostgresSink OR JsonlSink\n--postgres-url → PG\ndefault → scan_result.jsonl"]
    MS --> CS["TacticalWebhookSink\nC2_URL + C2_TOKEN\nhttps-only + SSRF-safe validated"]
    MS --> DS["DiscordSink\nDISCORD_WEBHOOK_URL\nHigh/Critical only"]
    MS --> TS["TimelineSink\nworkspace/logs/timeline.jsonl"]
    MS -.-> BBDS["BugBountyDraftSink\nworkspace/reports/drafts/\ninjected inside engine run"]
```

`PostgresSink` and `JsonlSink` are mutually exclusive. `BugBountyDraftSink` is added by `RedTeamEngine` inside `run_pipeline` and `run_autopilot` — not in `main.rs`.

---

## 4. Pipeline: 4-Stage Channel Topology

```mermaid
flowchart LR
    SRC[BoxStream TargetHost] -->|mpsc| S1

    subgraph S1[Stage 1: Discovery]
        BLOOM[Bloom filter\n1M cap / 1% FP\nno lock]
        DP[DiscoveryPlugins\nJoinSet concurrent]
        BLOOM --> DP
    end

    S1 -->|new subdomains loop back| S2
    S1 -->|original target| S2

    subgraph S2[Stage 2: Liveness]
        LC[LivenessChecker\nDNS + DoH]
        IP[is_safe_ip\nRFC1918 + loopback guard]
        CDN[CdnCheck gate\nskip_heavy_scan flag]
        LC --> IP --> CDN
    end

    S2 -->|live targets| S3

    subgraph S3[Stage 3: Scanning\nOrchestrator]
        FOR[for_each_concurrent N]
        MEM[Memory semaphore\nhard_limit permit]
        LP[LayerPolicy\nScanLayer gate]
        AG[ApprovalGate\nLayer 3+ confirm]
        PLUG[plugin.scan target\ntimeout + sandbox]
        FOR --> MEM --> LP --> AG --> PLUG
    end

    S3 -->|feedback_tx new assets| S2
    S3 -->|sink_tx| S4

    subgraph S4[Stage 4: Sink]
        LFS[LockFreeResultSink\nbackground worker thread]
        ENR[CVE cache enrich\nCveCacheManager global]
        FPF[FalsePositiveFilter]
        LFS --> ENR --> FPF --> WRITE[MultiSink.write]
    end
```

**Bypass rules:**
- `TargetType::Mobile` and `TargetType::Container` skip Stage 1 and Stage 2 entirely.
- CDN-detected targets have `skip_heavy_scan = true`; heavy scanner plugins check this flag.

---

## 5. Orchestrator: Plugin Execution Model

```mermaid
flowchart TD
    IN["scan_rx: mpsc::Receiver"] --> UNFOLD["stream::unfold<br/>shutdown-aware drain"]
    UNFOLD --> FOR["for_each_concurrent<br/>concurrency limit"]
    FOR --> MEM{"Semaphore permit<br/>RAM pressure guard"}
    MEM --> SCOPE{"StrictScope check<br/>fail-closed if out"}
    SCOPE -- fail --> AUDIT["AUDIT finding to sink"]
    SCOPE -- pass --> LAYER{"ScanLayer <= max_layer?"}
    LAYER -- blocked --> DEAD["Dead status to sink"]
    LAYER -- ok --> GATE{"ApprovalGate<br/>Layer 3+ = Verification<br/>Layer 4+ = Exploitation"}
    GATE -- denied --> DEAD
    GATE -- approved --> BA["BlackArch bridge<br/>tool suggestions appended"]
    BA --> RUN["plugin.scan<br/>SandboxDispatcher<br/>StealthExecutor"]
    RUN --> DASH["broadcast_tx<br/>Dashboard live feed"]
    RUN --> FEED["feedback_tx<br/>new discovered assets to S2"]
    RUN --> OUT["sink_tx to Stage 4"]

    SWARM{"swarm_mode?"} -- yes --> AROUTER["TieredAIRouter.decide_action<br/>next plugin + context"]
    AROUTER --> RUN
    OUT --> SWARM
```

**Priority Scheduling (V14.6):**
The Orchestrator implements a two-round dispatch model to ensure critical scanners run first:
1. **Round 1 (Priority)**: Plugins listed in `tactical_context["priority_plugins"]` (e.g., `auth_state_machine` for SSO subdomains).
2. **Round 2 (Standard)**: All other plugins matching capability/layer requirements.

**ScanLayer hierarchy** (`capability_layer.rs`):
```
Passive(0) < Discovery(1) < Scanning(2) < Verification(3) < Exploitation(4) < PostExploitation(5)
```
Default: `Scanning`. Unlock with `--max-layer exploitation`.

---

## 6. AI Router: Tiered Intelligence Cascade

```mermaid
flowchart TD
    F["Finding + TargetHost"] --> CL["classify<br/>CVSS + Category + WAF tech detection"]
    CL -->|CVSS >= 8.5 OR CredentialLeak| PR["RouteLevel::Premium"]
    CL -->|CVSS >= 5.0 OR WAF detected| MI["RouteLevel::Mid"]
    CL -->|else OR source_aware| LO["RouteLevel::Local"]

    PR & MI & LO --> CACHE{"moka cache hit?<br/>5000 entries / 2h TTL"}
    CACHE -- hit --> RET["return cached AIAnalysis"]
    CACHE -- miss --> SK["SkillManager.match_for_context<br/>TTP injection<br/>Local=300 Mid=800 Premium=1500 tokens"]
    SK --> TO["TokenOptimizer<br/>Lite / Full / Ultra"]
    TO --> CASCADE["Provider cascade<br/>Local → Mid → Premium on error"]

    subgraph Tier0["Local - Ollama"]
        OL["qwen2.5-coder:7b"]
    end
    subgraph Tier1["Mid"]
        AZ["Azure GPT-4o-mini p0"]
        OA["OpenAI GPT-4o-mini p1"]
        GF["Gemini 1.5-flash p2"]
    end
    subgraph Tier2["Premium"]
        GP["Gemini 1.5-pro p0"]
        AN["Anthropic claude-3-5-sonnet p1"]
        KI["Kimi kimi-for-coding p1"]
        CC["ClaudeCode SDK p2"]
        AG["Antigravity bridge p5"]
    end

    CASCADE --> Tier0 & Tier1 & Tier2
```

**Routing rules:**
- `source_aware` evidence type → always Local (no cloud API burn for code analysis).
- WAF/CDN tech (Cloudflare, Akamai, Incapsula, etc.) → escalate to at least Mid.
- Cache key = `SipHash-1-3(host + ip + finding_id + category)` — HashDoS resistant.
- `401 Unauthorized` from provider → log critical, continue cascade.
- Injection cache: 1000 entries, 30-min TTL — prevents redundant SkillManager calls.

---

## 7. Autonomous Agent Loop (--autonomous)

```mermaid
sequenceDiagram
    TGT->>PIPE: spawn discovery
    loop per finding
        PIPE-->>CORR: Ingestor::ingest_finding
        CORR-->>ROUTER: get_context_summary (inside CE lock)
        ROUTER-->>ROUTER: analyze (AIAnalysis)
        alt risk_score ≥ 8 OR High/Critical
            ROUTER->>POC: validate finding
            POC-->>ROUTER: validated+evidence
        end
        ROUTER->>SINK: enriched TargetHost
        ROUTER->>ROUTER: decide_action → next plugin
        Note over ROUTER: loop continues with new findings
    end
    Note over CORR: On shutdown: CE::save(absolute_path) + Double-Hash MAC
```

All steps logged to `ActivityLog` → `workspace/logs/timeline.jsonl` (JSONL append-only). `AdaptiveContext` tracks current posture (Ghost/Strike/Breach) and `CavemanLevel` for prompt compression.

---

## 8. Plugin Taxonomy

| `reconnaissance` | always | 1-2 | cdncheck, tlsx, shodan, netlas, certstream, waymore, gitleaks, subfinder |
| `enumeration` | always | 2 | nuclei, katana, ffuf, shuffledns, s3scanner, cloudenum, rustscan |
| `exploitation` | always | 4 | gopherus, ssrfmap, ghauri, kxss, sqlmap, dalfox, hydra, impacket |
| `intelligence` | always | 1 | chaos, securitytrails, criminalip, greynoise, searchsploit |
| `verification` | always | 3 | PocValidator (AI-driven PoC generation + execution) |
| `detection_evasion` | always | any | StealthPolicy, HumanJitter |
| `reporting` | always | sink-side | BugBountyReport (H/C/M → MD), AttackChain consolidated |
| `compliance` | always | 2 | policy-file driven audit |
| `lateral_movement` | `sovereign` | 5 | AD coercion, Responder, Coercer |
| `persistence` | `sovereign` | 5 | WebShell, C2, SSH key inject, registry autorun |
| `privilege_escalation` | `sovereign` | 5 | CredentialInjection, ProcessInjection, Certipy, PrivescHunter |

`sovereign` feature flag gates all post-exploitation at compile time. Not compiled in default release builds.

---

## 9. Persistence Layer (PostgreSQL)

```mermaid
erDiagram
    scans ||--o{ targets : "1 scan → N targets"
    targets ||--o{ findings : "1 target → N findings"
    targets ||--o{ agent_sessions : "1 target → N sessions"
    findings ||--o{ submitted_reports : "1 finding → N platforms"

    scans {
        serial id PK
        text command_line
        timestamptz timestamp
    }
    targets {
        serial id PK
        int scan_id FK
        text host
        text ip
        text status
    }
    findings {
        text id PK
        int target_id FK
        text severity
        jsonb evidence
        jsonb enrichment
        jsonb context
    }
    agent_sessions {
        text id PK
        text agent_role
        int target_id FK
        text posture
        text memory_json
    }
    submitted_reports {
        bigserial id PK
        text finding_hash
        text program_handle
        text platform
        text submission_url
        timestamptz submitted_at
    }
    plugin_cache {
        text cache_key PK
        text output
    }
    scan_queue {
        serial id PK
        text host
        text status
        int priority
        text claimed_by FK
    }
    workers {
        text id PK
        text status
    }
    program_targets {
        serial id PK
        text program_name
        text platform
        text host
        bool is_in_scope
    }
```

3 migrations:
- `20260428` — core schema (scans, targets, findings, objectives, agent_sessions, plugin_cache, mcp_stats, checkpoints, deduplication, cve_cache)
- `20260506` — distributed worker queue (workers, scan_queue + priority index)
- `20260508` — bug bounty program targets (program_targets, h1/bc/intigriti platform column)
- `20260508000003` — [V14.7] bug bounty submission deduplication (`submitted_reports`)

---

## 10. Interfaces: Dashboard, MCP, Worker

```mermaid
flowchart LR
    subgraph Interfaces
        CLI["CLI<br/>--target / --input / --apk"]
        DASH["Web Dashboard<br/>Axum + Ed25519 JWT<br/>0o600 token file"]
        MCP["MCP SSE Server :3001<br/>Claude Code integration<br/>MCP_TOKEN auth"]
        WRK["Worker Node<br/>--worker + --nats-url<br/>claims from scan_queue PG"]
    end

    CLI & DASH & MCP & WRK --> ENG[RedTeamEngine]
    ENG --> PIPE[Pipeline stages 1-4]
    PIPE --> MSINK[MultiSink]

    DASH -->|MissionRequest mpsc| MQ["Mission Queue to injection_tx"]
    MQ --> PIPE
```

**Dashboard auth:** Ed25519 `SigningKey` generated per-session. JWT token written to `workspace/logs/dashboard.token` with `mode(0o600)`. Token valid 24h (`exp` claim).

**Worker mode:** polls `scan_queue` (PostgreSQL), claims via `claimed_by` field, runs the same `RedTeamEngine`. NATS kill-switch propagates `egress_lock` to all nodes.

---

## 11. OPSEC & Safety Gates

| Gate | Location | Effect |
|---|---|---|
| `validate_target` | main.rs ingestion | Rejects malformed targets before stream |
| `is_ssrf_safe_host_async` | C2 URL validation | Blocks private/loopback for webhook sinks |
| `is_safe_ip` | Stage 2 liveness | Blocks RFC1918/loopback resolved IPs |
| `ScanLayerPolicy` | Stage 3 orchestrator | Hard cap on destructive plugin layers |
| `ApprovalGate` | Stage 3 orchestrator | Requires human confirm for Layer 3+ |
| `ScopePolicy` | Stage 3 orchestrator | Fail-closed if target outside program scope |
| `ProxyManager::wait_for_readiness` | Engine startup | Blocks scan until stealth infra is ready |
| `CancellationToken` | All stages | Graceful drain on Ctrl-C; no finding loss |
| `SSRF-safe C2_URL` | TacticalWebhookSink | `https`-only + SSRF guard before registration |
| `ParentDir traversal check` | CorrelationEngine `save`/`load` | Rejects any path with `..` components via `Component::ParentDir` match |
| `Double-Hash MAC` | CorrelationEngine | `SHA256(K \|\| SHA256(K \|\| D))` prevents length-extension attacks + state poisoning |
| `Mandatory Secret` | CorrelationEngine | `MCP_TOKEN` required for persistence; bails if missing |
| `Absolute Path` | SwarmOrchestrator | `dirs::data_local_dir` prevents CWD dependency issues |
