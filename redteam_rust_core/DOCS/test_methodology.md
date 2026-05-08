# 🧪 Test Methodology: Sentinel vs. Manual (50/50 Split)

## Goal
Determine if the automation provided by Sentinel/Mimikri offers a measurable competitive advantage ("moat") over a standard manual workflow using modern tools (Caido, bbscope, notify).

## Pre-requisite: Phase 0 Baseline (2 Weeks)
Before the 50/50 split, a **Telemetry Baseline** must be established:
1. **Passive Observation**: Run the system for 14 days without ROI-based filtering.
2. **Metric Collection**: Log all `premium_llm_calls`, `findings_in`, and `fpf_drops`.
3. **Calibration**: Adjust `ProgramAnalyzer` weights and FPF thresholds based on real-world ratios observed in this phase.

## Methodology

### 1. Program Selection & Pairing (N ≥ 2)
Select pairs of programs with matched profiles.
- **Pairing Formula**: 
  `|median_payout_a - median_payout_b| / max < 0.3` AND `|reports_resolved_a - reports_resolved_b| / max < 0.3`
- **Matched Pairs Examples**:
  - Pair 1: Yahoo (Wildcard) + Uber (Wildcard).
  - Pair 2: Mail.ru (Broad scope) + Mapbox (Broad scope).

### 2. Timeframe & Concrete Schedule (4 Weeks)
- **Duration**: 4 calendar weeks.
- **Hours**: 20h/week per group (Total 160h).
- **Concrete Shift Control**:
  - **Even Days**: Group A (Manual) 09:00-13:00 | Group B (Sentinel) 14:00-18:00.
  - **Odd Days**: Group B (Sentinel) 09:00-13:00 | Group A (Manual) 14:00-18:00.
  This eliminates both morning bias and late-day fatigue bias.

### 3. Groups
- **Group A (Manual Control)**: Hunter uses Caido + bbscope + Notify. Discovery and verification are 100% manual.
- **Group B (Sentinel/Mimikri)**: Full pipeline enabled with Swarm Orchestration. Hunter only intervenes for final verification.

### 4. Metrics (ROI Rubric)
- `Findings_Total`: Raw issues identified.
- `Reports_Hr`: Reports submitted to platform per operational hour.
- `Accepted_Hr`: Accepted/Triaged reports per operational hour.
- `Bounty_Hr ($/hr)`: Total Payouts / Total Hours.
- `Signal_to_Noise`: `Accepted` / `Total`.

### 5. Success Criteria (1.5x)
Sentinel is "Value-Positive" if `Bounty_Hr` in Group B is **>1.5x** Group A.
- **Note**: This ratio assumes dev-time for Sentinel is a **sunk cost**. If dev-amortization is included, the threshold may be adjusted.
- If ratio is **<1.0x**, we pivot to manual-assist tools only.

## 6. Pattern Identification (Fase 4)
Signatures must be stable across runs to allow effective weight adjustment in the `CorrelationEngine`.
Finding Signature: `Category:Severity:Id`.
Chain Signature: `Join(NodeIds)`.
