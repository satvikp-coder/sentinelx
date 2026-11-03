# Sentinel X — Reproducible Local Verification Guide

**Date:** 2026-11-03
**Worker branch:** work/ds
**Worker SHA:** 1933b80
**Python:** C:\Users\satvi\Desktop\sentinelx-ds\.venv\Scripts\python.exe

---

## Prerequisites

| Tool | Version | Required for |
|------|---------|--------------|
| Python | 3.11+ | All Python tests, Ruff |
| Node.js | 24.x | TypeScript SDK, React dashboard |
| npm | 11.x | TypeScript SDK, React dashboard |
| Docker Desktop | 29.7.2+ | PHP lab tests (optional) |
| Playwright Chromium | 1.64.1+ | Browser E2E tests (optional) |

---

## Step 1: Verify Python Environment

```cmd
cd C:\Users\satvi\Desktop\sentinelx-ds
.venv\Scripts\python.exe --version
.venv\Scripts\python.exe -m pip list | findstr ruff pytest
```

Expected: Python 3.13.14, ruff >= 0.6, pytest >= 8.

---

## Step 2: Run Project-wide Ruff

```cmd
cd C:\Users\satvi\Desktop\sentinelx-ds
.venv\Scripts\python.exe -m ruff check .
```

Expected: "All checks passed!" (0 errors)

---

## Step 3: Run Full Fast Python Suite

```cmd
cd C:\Users\satvi\Desktop\sentinelx-ds
.venv\Scripts\python.exe -m pytest -m "not slow" -p no:cacheprovider --basetemp=%TEMP%\opencode\verify
```

Expected: "1363 passed, 0 failed, 150 deselected" (exit code 0, ~8 minutes)

Use a fresh unique `--basetemp` outside both worktrees for each run.

---

## Step 4: Run Focused Test Suites

```cmd
cd C:\Users\satvi\Desktop\sentinelx-ds

# API + Security Repair tests
.venv\Scripts\python.exe -m pytest tests/unit/test_api_units.py tests/unit/test_api_security_repair2.py -p no:cacheprovider --basetemp=%TEMP%\opencode\api_verify

# Metrics + Evidence tests
.venv\Scripts\python.exe -m pytest tests/unit/test_metrics.py tests/unit/test_evidence_store.py -p no:cacheprovider --basetemp=%TEMP%\opencode\metrics_verify

# Final run + Agent Guard SDK tests
.venv\Scripts\python.exe -m pytest tests/unit/test_final_run.py tests/unit/test_agent_guard_sdk.py -p no:cacheprovider --basetemp=%TEMP%\opencode\guard_verify
```

Expected: All tests pass, exit code 0.

---

## Step 5: Verify TypeScript SDK

```cmd
cd C:\Users\satvi\Desktop\sentinelx-ds\sdk\typescript
npx tsc --noEmit
```

Expected: No output (0 errors), exit code 0.

---

## Step 6: Verify React Dashboard

```cmd
cd C:\Users\satvi\Desktop\sentinelx-ds/apps/web
npm install   # if node_modules not present
npx tsc --noEmit
npx vite build
```

Expected: TypeScript 0 errors, Vite build success with dist/ output.

---

## Step 7: Run npm Audit

```cmd
cd C:\Users\satvi\Desktop\sentinelx-ds/apps/web
npm audit
```

Expected: "0 vulnerabilities"

---

## Step 8: Verify Git State

```cmd
cd C:\Users\satvi\Desktop\sentinelx-ds
git status --short
git log --oneline -5
git diff --check
```

Expected: Clean working tree, current SHA 1933b80, `git diff --check` exit 0.

---

## Step 9: Verify Forbidden Paths Unchanged

```cmd
cd C:\Users\satvi\Desktop\sentinelx-ds
git diff 83030082641fca857df39f0db77ae4024efcbc21 -- packages/policy/ configs/policy/ packages/scanner/authz.py packages/scanner/http.py labs/ *_reference/ .env
```

Expected: Empty output (no changes to protected paths).

---

## Expected Full Results Summary

| Check | Command | Expected Result |
|-------|---------|-----------------|
| Ruff | `ruff check .` | All checks passed |
| Full fast suite | `pytest -m "not slow"` | 1363 passed, 0 failed |
| TypeScript SDK | `tsc --noEmit` | 0 errors |
| React build | `vite build` | success |
| npm audit | `npm audit` | 0 vulnerabilities |
| git diff --check | `git diff --check` | exit 0 |

---

## Optional: Docker-dependent Tests (requires Docker Desktop)

```cmd
cd C:\Users\satvi\Desktop\sentinelx-ds
# Start Docker Desktop first, then:
.venv\Scripts\python.exe -m pytest tests/integration/test_labs.py -k php -p no:cacheprovider --basetemp=%TEMP%\opencode\php_verify
```

---

## Optional: Browser E2E Tests (requires Playwright)

```cmd
cd C:\Users\satvi\Desktop\sentinelx-ds
playwright install chromium
.venv\Scripts\python.exe -m pytest -m browser -p no:cacheprovider --basetemp=%TEMP%\opencode\browser_verify
```

---

## Notes

- Always use `-p no:cacheprovider` to avoid cache issues.
- Always use a fresh unique `--basetemp` outside both worktrees.
- Do not run destructive commands (`reset --hard`, `clean`, etc.).
- Do not push or merge without independent review.
- All model-related results are from scripted/planned agents, clearly labeled SIMULATED.
- Scans stay PENDING and shields stay PROPOSED; execution/activation pipeline not yet built.
