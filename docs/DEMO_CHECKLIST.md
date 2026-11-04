# Sentinel X — Historical Demo Checklist

Superseded for submission by [SUBMISSION_DEMO_SCRIPT.md](SUBMISSION_DEMO_SCRIPT.md)
and [SUBMISSION_RECORDING_GUIDE.md](SUBMISSION_RECORDING_GUIDE.md). Do not assume
the planned attack-success or recall claims below occurred; use actual run output.

## Pre-Demo

- [ ] Lab `vibe_notes_node` is running: `python scripts/lab_up.py vibe_notes_node`
- [ ] Lab `vibe_shop_php` is running (Docker required): `python scripts/lab_up.py vibe_shop_php`
- [ ] Docker daemon is running (for PHP lab tests)
- [ ] Python venv activated: `.venv\Scripts\activate`
- [ ] No live model credentials needed for demo (all scripted paths)
- [ ] Screen recorder ready (3-minute max)
- [ ] No real credentials or secrets visible on screen
- [ ] Browser not needed for demo (all CLI/API driven)

## Demo Segments (3 minutes)

### 0:00 — Problem
- [ ] Diagram showing agent injection risk
- [ ] Clear problem statement (under 30 seconds)

### 0:15 — Legitimate Agent Task
- [ ] `sentinelx agent test --adapter scripted:s1:8080 --lab vibe_notes_node --scenario S1`
- [ ] Arm A and Arm B both complete
- [ ] Show task completion metric: 1/1

### 0:30 — Unprotected vs Protected
- [ ] Run attack scenario (role spoofing or misleading workflow)
- [ ] Arm A: attack succeeds (forbidden outcome occurs)
- [ ] Arm B: attack blocked (no forbidden outcome)
- [ ] Show ATTEMPTED vs EXECUTED distinction

### 0:55 — Independent Evidence Verifier
- [ ] Show model-written claims with cited event IDs
- [ ] Show verifier checking claims against evidence
- [ ] Show citation fidelity metric

### 1:10 — EVCS
- [ ] Show containment branch outcomes
- [ ] Show BLOCK_ONLY recommendation

### 1:25 — Site Scanner and Fix Engine
- [ ] Run scanner against local lab
- [ ] Show findings with planted ground truth recall
- [ ] Show fix proposals (not auto-applied)

### 2:05 — Live Temporary Shield
- [ ] Show shield rules in monitor and enforce mode
- [ ] Show TEMPORARY SHIELD, NOT A FIX label
- [ ] Show kill switch

### 2:35 — Evaluation and Limitations
- [ ] Show static report with real numerators/denominators
- [ ] Honestly state limitations

## Post-Demo

- [ ] Stop labs: `python scripts/lab_down.py vibe_notes_node` (and vibe_shop_php)
- [ ] Review recording (must be under 3 minutes)
- [ ] Verify no secrets or credentials leaked
- [ ] Verify all metrics shown are real (not fabricated)

## What to Emphasize

- Models propose; gateways enforce; verifiers confirm
- ATTEMPTED ≠ EXECUTED
- TEMPORARY SHIELD, NOT A FIX
- All numbers are real numerators/denominators from backend data
- SIMULATED/RECORDED/LIVE labels are shown

## What to Avoid

- Do not show live model calls (no credentials)
- Do not show public targets
- Do not show real credentials
- Do not fabricate metrics or screenshots
- Do not exceed 3 minutes
