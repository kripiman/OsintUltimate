# Engine Core: Sovereign Pipeline
 
 > Source-verified. Replaces `engine_core.original.md`. See `ARCHITECTURE.md` for full diagrams. Last verified: 2026-05-13 (V15.1 Hardened).
 
 ---
 
 ## Overview
 
 The engine is a 4-stage async pipeline built on `tokio::mpsc` channels. Each stage runs as an independent `tokio::spawn` task. Stages communicate only via channels — no shared mutable state between stages.
 
 Entry point: `RedTeamEngine::run_pipeline()` or `run_autopilot()` in `src/core/engine/app.rs`.
 
 ---
 
 ## Stage 1: Discovery
 
 **File:** `src/core/pipeline.rs` → `spawn_discovery_stage`
 
 - Bloom filter (1M capacity, 1% FP rate) deduplicates hosts without locking.
 - All `DiscoveryPlugin` instances run concurrently via `tokio::task::JoinSet`.
 - Each discovered subdomain becomes a new `TargetHost` and is forwarded to Stage 2 directly.
 - Original target also forwarded to Stage 2 after discovery completes.
 - `TargetType::Mobile` and `TargetType::Container` bypass this stage entirely.
 
 **Discovery plugins** (`src/plugins/reconnaissance/`): passive subdomain enumeration (subfinder, amass, waymore), ASN expansion (asnmap), certificate transparency (certstream), ChaosDB, SecurityTrails, Netlas, Shodan, GitHub dorks.
 
 ---
 
 ## Stage 2: Liveness Verification
 
 **File:** `src/core/pipeline.rs` → `spawn_liveness_stage`
 
 Three sequential checks before a target proceeds to scanning:
 
 1. **DNS Resolution** — `LivenessChecker::is_live()`. Supports standard DNS and DoH (`--doh`).
 2. **IP Safety** — `is_safe_ip()` blocks RFC1918, loopback, link-local. Prevents DNS rebinding attacks during scan execution (IP is pinned to `resolved_ip`).
 3. **CDN Gate** — `CdnCheckScanner::is_cdn()`. Sets `skip_heavy_scan = true` for CDN-protected targets; heavy scanner plugins respect this flag to avoid wasting resources.
 
 Failed liveness → target status set to `Dead`, forwarded directly to Stage 4 (sink) with no further scanning.
 
 ---
 
 ## Stage 3: Scanning (Orchestrator)
 
 **File:** `src/core/orchestrator.rs`
 
 Runs all scanner plugins against each live target. Key mechanisms:
 
 ### Concurrency Control
 ```
 for_each_concurrent(concurrency_limit, |target| { ... })
 ```
 `concurrency` from CLI (`--concurrency`) or auto-detected by `EngineFactory`. Memory semaphore (`hard_limit_mb` permits) provides back-pressure against RAM exhaustion.
 
 ### Plugin Execution Chain
 ```
 ScopePolicy check → LayerPolicy check → ApprovalGate → BlackArchBridge → SandboxDispatcher → plugin.scan()
 ```
 
 | Guard | Purpose |
 |---|---|
 | `ScopePolicy` | Fail-closed if target not in program scope (strict_scope mode) |
 | `ScanLayerPolicy` | Hard cap at `max_layer`; plugins above layer are skipped |
 | `ApprovalGate` | Layer 3+ (Verification) and Layer 4+ (Exploitation) require operator confirm |
 | `BlackArchBridge` | Enriches target with suggestions of available BlackArch tools |
 | `SandboxDispatcher` | Runs external tools in isolated Docker environment with proxy routing |
 
 ### Shutdown Drain
 On `CancellationToken` cancellation, `Orchestrator` explicitly drains the remaining channel items (marks as `Dead`) before exiting. No target is silently discarded.
 
 ### Feedback Loop
 `feedback_tx: Option<mpsc::Sender<TargetHost>>` allows scanner plugins to inject newly discovered assets (e.g., a scanner finds a live subdomain) directly back into Stage 2 for liveness verification. This is the "recursion" mechanism enabling deep discovery.
 
 ### Swarm Mode (`--swarm`)
 When enabled, `TieredAIRouter::decide_action()` is called after each finding to select the next plugin to run. Creates an adaptive, AI-directed scan sequence rather than running all plugins sequentially.
 
 ---
 
 ## Stage 4: Sink (Lock-Free)
 
 **File:** `src/core/pipeline.rs` → `run_sink_stage` / `src/core/lock_free_sink.rs`
 
 - `LockFreeResultSink` runs a background worker thread with a crossbeam queue. The pipeline never blocks waiting for I/O writes.
 - Before writing, each target goes through:
   1. **CVE Enrichment** — `CveCacheManager::global()` looks up CVE data for findings (PostgreSQL-backed or in-memory).
   2. **False Positive Filter** — `FalsePositiveFilter::evaluate()` drops known FP patterns.
 - After filtering, `MultiSink::write(target)` fans out to all attached sinks.
 
 ---
 
 ## Autonomous Mode (`--autonomous`)
 
 **File:** `src/core/agent.rs`
 
 Instead of running all plugins sequentially, `AutonomousAgent`:
 1. Runs discovery via `pipeline.run_discovery()` → receives a stream of findings.
 2. For each finding: correlates via `CorrelationEngine`, routes to `TieredAIRouter::analyze()`.
 3. High-risk findings (risk_score ≥ 8 or High/Critical severity) → `PocValidator::validate()` generates and executes a proof-of-concept.
 4. `TieredAIRouter::decide_action()` selects the next plugin based on current context.
 5. All steps logged to `ActivityLog` → `workspace/logs/timeline.jsonl`.
 
 The agent uses `AdaptiveContext` to track mission posture (Ghost/Strike/Breach) and adjusts token compression level (`CavemanLevel`) accordingly.
 
 ---
 
## Correlation Engine (V15.1)

**File:** `src/core/correlation/mod.rs`

The `CorrelationEngine` (CE) builds a dynamic `AttackGraph` of the environment. In V15.1, it has been hardened against memory exhaustion and state poisoning:

### Decoupling (ARCH-8)
- **Ingestor Pattern**: Finding ingestion is decoupled via `Ingestor::ingest_finding(ce, finding)`. The CE itself is a data structure; `Ingestor` owns all correlation logic.
- **Node Limit**: `MAX_NODES = 10,000` hard cap. `Ingestor` drops new findings if graph is at capacity, preventing OOM.

### State Persistence (ARCH-9)
- **Absolute Paths**: `dirs::data_local_dir()` resolves to `~/.local/share/osint-ultimate/swarm_ce_state.json`. Eliminates CWD-relative path failures.
- **ParentDir Traversal Guard**: Both `save()` and `load()` iterate `path.components()` and reject any `Component::ParentDir` (`..`) — replaces the deprecated `contains("/")` check.
- **Double-Hash MAC**: `signature = SHA256(secret || SHA256(secret || data_json))` (payload version `"1.2"`).
    - Prevents length-extension attacks and manual state tampering.
    - `MCP_TOKEN` env var is mandatory. System bails with error if unset.
- **Dirty Flag**: `is_dirty: bool` — O(1) cache invalidation. Path recalc only when graph mutated.

### Graph Analysis (ARCH-10)
- **MAX_DEPTH = 8** (`analyzer.rs`): DFS capped at 8 hops, preventing recursive explosion in dense AD environments.
- **Root Node Selection**: `find_all_paths()` starts only from `Recon | NetworkPort | TechnologyStack` category nodes.
- **Owned-Node Paths**: `find_paths_from_owned()` starts from `AD-NODE-{sid}` format IDs in the owned set.
- **Signature Deduplication**: `::[v15]::` separator in `pattern_signature()` prevents node-ID collision in chain hashing.

---

 ## Memory Safety Architecture
 
 ```
 MemoryMonitor (soft_limit_mb, hard_limit_mb)
     │
     ├── Soft limit → log warning, reduce batch size
     └── Hard limit → Semaphore blocks new plugin spawns
 ```
 
 Configured via `SOFT_MEMORY_LIMIT` / `HARD_MEMORY_LIMIT` env vars (defaults: 600MB / 900MB). Auto-scaled by hardware profile detection.
 
 ---
 
 ## Key Design Decisions
 
 | Decision | Rationale |
 |---|---|
 | mpsc channels between stages | Back-pressure without shared mutex; stages operate independently |
 | Bloom filter in Stage 1 | O(1) dedup without a HashSet lock under high concurrency |
 | `LockFreeResultSink` | Sink I/O (PG inserts, file writes) must not block the scan pipeline |
 | IP pinned at liveness stage | Prevents DNS rebinding during multi-plugin scan of same host |
 | `CancellationToken` drain | Guarantees no target is silently dropped on shutdown |
 | `GlobalConfig` passed by clone | Avoids lifetime coupling between engine and plugins; `Arc<>` fields inside keep it cheap |
 
 ---
 
 > **Fail-Closed Guarantee:** If the liveness check resolves to an unsafe IP, or if the scope policy rejects the target, the system does NOT attempt to scan. The target is marked `Dead` and written to the sink as-is. No plugin runs on unverified targets.
