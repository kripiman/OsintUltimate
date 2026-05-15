# AUDIT_PHASE1.md - Orchestrator Domain Decomposition Review

## 審 Phase 1 計劃 (Review of Phase 1 Plan)

### 現狀 (Verified Baseline)
- **HEAD**: 470d776.
- **Phase 0 Baseline**: `golden_baseline.json` created.
- **MEMORIA**: "ARCH-11 READY".
- **Refactoring Progress**: `core/orchestrator/` already has `dispatch/enrichment/monitor/reactive/scope_guard`.
- **Monoliths**: `core/swarm/orchestrator.rs` is 27.5K (monolith).

### 計劃審 (Verdict by Section)

#### ✓ 合理 (Reasonable)
- **SRP Enforcement**: Breaking down `swarm/orchestrator.rs` is mandatory for Sovereign-grade architecture.
- **C2/Sliver Decoupling**: Moving `SliverAutomator` and `SliverFeedbackLoop` to `c2/` domain.
- **Architecture Pattern**: Domain-based grouping > layer-based grouping.

#### ⚠ 缺漏 (Missing Items)
1. **Phase 0 Parity Gate**: Verification must pass using Phase 0 baseline (L1<2%, L2 hash, L3 typeid).
2. **Atomic Commit Sequence**:
   - C1: New `orchestrator/swarm/` (empty mod).
   - C2: Move + Redirect imports (build pass).
   - C3: Extract agent/correlation sub-files (test pass).
   - C4: Delete legacy `core/swarm/`.
3. **Lifecycle Domain Definition**: Must include `shutdown_coordinator`, `droplet cleanup`, `state-save`, and the existing `monitor.rs`.
4. **CorrelationEngine State Migration**: Ownership (Arc) must be elevated to upper layer or passed via context.
5. **Backward Compatibility**: CLI `--sliver-*` flags must be preserved via `serde alias` in `InfrastructureConfig`.

#### ✗ 問題 (Issues)
6. **Deterministic Swarm Testing**: Verification plan must include dual-run zero-byte diff check.
7. **PR Size Control**: Split work into 4 atomic PRs/stages to ensure review quality.
8. **CI Parity Job**: `.github/workflows/parity.yml` must block merge.

### 建議架構 (Proposed Architecture)

```
core/orchestrator/
├── mod.rs              ← 公共 API, 工廠
├── lifecycle/          ← shutdown, monitor, droplet kill-switch
│   ├── mod.rs
│   ├── monitor.rs      ← 從 orchestrator/monitor.rs 移
│   └── shutdown.rs
├── dispatch/           ← 現 dispatch.rs 升域
├── reactive/           ← 現 reactive.rs 升域 (+ attack_graph)
├── enrichment/         ← 現 enrichment.rs 升域
├── scope/              ← scope_guard.rs
├── swarm/              ← 新
│   ├── mod.rs
│   ├── agent.rs        ← Scout/Exploiter/C2Operator/Reporter trait + impl
│   ├── correlation.rs  ← CorrelationEngine ingestion
│   ├── budget.rs       ← 移 swarm/budget.rs
│   └── inventory.rs    ← 移 swarm/inventory.rs
└── c2/                 ← 新
    ├── mod.rs
    ├── sliver.rs       ← SliverAutomator
    └── feedback.rs     ← SliverFeedbackLoop (gRPC)
```

**Note**: `NvdMonitor` should move to `intelligence/` or `enrichment/`, not `swarm/`.

### 退出條件 (Exit Gates)

| Gate | Check | Source |
|------|-------|--------|
| G1 | cargo build --release 0 warn | local |
| G2 | cargo test --package redteam_rust_core PASS | local |
| G3 | cargo clippy -- -D warnings PASS | local |
| G4 | verify_parity L1<2% L2 hash L3 typeid PASS | parity.yml |
| G5 | swarm dual-run determinism diff = 0 byte | manual |
| G6 | CLI --swarm smoke test PASS (DVWA target) | manual |

**VERDICT**: Conditional Approval based on completion of the above items.
