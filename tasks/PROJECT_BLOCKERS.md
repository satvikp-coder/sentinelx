# Sentinel X — Project Blockers

**Audit date:** 2026-11-03
**Worker branch:** work/ds
**Worker SHA:** 51e99d8

---

## BLOCKERS REQUIRING HUMAN ACTION

### 1. License choice (owner decision)
**Why:** The repository will be made public for hackathon submission. A license file is required.
**Prerequisites:** Owner selects a license (MIT, Apache-2.0, etc.)
**Expected cost/risk:** Low
**Safe command/procedure:** Add LICENSE file to repository root
**Expected evidence:** LICENSE file present, NOTICE.md updated if needed
**Who must authorize/execute:** Owner

### 2. Public repository visibility (owner decision)
**Why:** Hackathon submission requires a public repository.
**Prerequisites:** License chosen first
**Expected cost/risk:** Low (repository becomes publicly viewable)
**Safe command/procedure:** Change repository visibility on GitHub (web UI)
**Expected evidence:** Repository is public
**Who must authorize/execute:** Owner

### 3. Demo video recording (3 minutes)
**Why:** Hackathon submission requires a 3-minute demo video.
**Prerequisites:** All features implemented and locally verified
**Expected cost/risk:** Low
**Safe command/procedure:** Record per docs/DEMO_SCRIPT.md
**Expected evidence:** Demo video file
**Who must authorize/execute:** Owner

### 4. Hackathon submission
**Why:** Nov 4, 9 PM ET deadline on Cerebral Valley portal.
**Prerequisites:** All of the above + public repository
**Expected cost/risk:** Low
**Safe command/procedure:** Submit via portal
**Expected evidence:** Submission confirmation
**Who must authorize/execute:** Owner

---

## BLOCKERS REQUIRING EXTERNAL RESOURCES

### 5. Live model benchmark (Task 25)
**Why:** Validates model-driven arm against protected arm; currently only scripted/planner results are available.
**Prerequisites:** Model API credentials (NVIDIA integrate.api.nvidia.com or Baseten), budget controls
**Expected cost/risk:** Within $70 hard cap ($50 warning threshold)
**Safe command/procedure:** `python scripts/run_experiment.py --manifest evaluations/manifest.json` with live model provider configured
**Expected evidence:** Evaluation report with live model results
**Who must authorize/execute:** Owner (provides credentials)

### 6. Docker Desktop daemon (Task 23/30 PHP scanner tests)
**Why:** PHP lab (vibe_shop_php) requires Docker for scanner validation.
**Prerequisites:** Docker Desktop installed and running
**Expected cost/risk:** Low
**Safe command/procedure:** Start Docker Desktop; run `pytest tests/integration/test_labs.py -k php`
**Expected evidence:** PHP scanner tests pass
**Who must authorize/execute:** Owner

### 7. Playwright Chromium (Task 29 browser E2E)
**Why:** React dashboard browser E2E tests.
**Prerequisites:** `playwright install chromium` (large download)
**Expected cost/risk:** Low (disk space + download)
**Safe command/procedure:** `playwright install chromium`; run `pytest -m browser`
**Expected evidence:** Browser tests pass
**Who must authorize/execute:** Owner

---

## BLOCKERS REQUIRING CI INFRASTRUCTURE

### 8. GitHub Actions CI run
**Why:** Verify CI configuration (.github/workflows/ci.yml) passes on pushed commits.
**Prerequisites:** Repository pushed to origin
**Expected cost/risk:** Low
**Safe command/procedure:** Push work/ds branch; check Actions tab
**Expected evidence:** CI run green
**Who must authorize/execute:** Owner (push not authorized in this session)

---

## NON-BLOCKERS (documented limitations)

| Item | Status | Why not a blocker |
|------|--------|-------------------|
| CRLF git apply on Windows | Documented | Linux CRLF patches apply cleanly; Windows git limitation |
| Tailwind @tailwind not processed | Documented | Structural layout works; styling not required for functionality |
| LICENSE not chosen | Documented | Owner decision; doesn't affect code correctness |
| Repo not public | Documented | Owner decision; doesn't affect code correctness |
| No live model runs | Documented | All results are from scripted/planned agents; clearly labeled SIMULATED |

---

## RESOLVED IN THIS SESSION

| Blocker | Resolution |
|---------|------------|
| Ruff 23 errors | Fixed all: StrEnum conversions, unused imports, long lines, import sorting |
| Node lab loopback test (2 failures) | Replaced psutil.net_connections() with socket bind tests (Windows-compatible) |
| test_rate_limit_burst (timing-dependent) | Made deterministic: pre-fill bucket, verify 429/200 via HTTP |
| Security Repair 3 final blocker (error response redaction) | Generic 400 message instead of raw ValidationError; regression test added |
| Security Repair 3 blockers (cancellation, approval storage, evidence persist-before-broadcast, report crash) | All fixed and verified |
