# Shield Recovery — Real E2E Evidence

**Date:** 2026-11-04

## Architecture (one control plane, one runtime contract)

```
+--------------------+        SHIELD_RUNTIME_DB (SQLite, WAL)        +----------------------+
|  API / control     |  ------------------------------------------>  |  Standalone proxy    |
|  plane (FastAPI)   |   rows: payload + status + rule_hash          |  (uvicorn, :18090)   |
|                    |                                               |                      |
|  - RuleCompiler    |   PROPOSED -> ACTIVE -> EXPIRED/REMOVED       |  - ShieldProxy       |
|  - approvals       |                                               |  - enforces ACTIVE   |
|  - benign gate     |                                               |    rows whose hash   |
|  - activation      |                                               |    validates         |
+--------------------+                                               +----------+-----------+
                                                                                |
                                                                    loopback HTTP to
                                                                    authorized upstream
                                                                    (127.0.0.1 only)
```

- The API is the only writer of rule state transitions.
- The proxy **never** enforces a row marked ACTIVE unless the payload parses as
  a valid `ShieldRule` AND its `canonical_rule_hash` matches the recorded hash.
- Trust boundary (documented): filesystem access to the runtime DB is control
  plane authority; the DB is local-only and the proxy listens on loopback.
  No network control interface exists; no secret is hardcoded.

## Demonstrated workflow (test_e2e02_separate_proxy_process_enforces_api_activation)

Real OS processes:
- Disposable upstream: `ThreadingHTTPServer` on a free 127.0.0.1 port (test process).
- Standalone proxy: `python -m uvicorn sentinelx.shield.server:create_shield_app`
  in a **separate subprocess** with `SHIELD_MODE=enforce`,
  `SHIELD_LAB_MODE=1`, `SHIELD_RUNTIME_DB=<tmp>/runtime.db`.
- API: TestClient with the same `SHIELD_RUNTIME_DB`.

Observed results (actual assertions from the passing test):

| Step | Action | Observed |
|------|--------|----------|
| 1 | GET /api/procsecret through subprocess proxy before activation | 200, upstream counter +1 |
| 2 | Public propose | 200, state PROPOSED |
| 3 | Public approval (`/api/v1/approvals`, tool=shield_rule) | 200 |
| 4 | Public activation (`/api/v1/shield/rules/{id}/approve`) | 200, state ACTIVE |
| 5 | GET /api/procsecret through subprocess proxy | **403**, upstream counter unchanged |
| 6 | GET /health through subprocess proxy | 200 (benign unaffected) |
| 7 | Public removal (`DELETE /api/v1/shield/rules/{id}`) | 200, runtime_enforcement_stopped=true |
| 8 | GET /api/procsecret through subprocess proxy | 200, upstream counter +1 (enforcement stopped) |

## In-process proxy path (test_e2e_full_lifecycle_block_and_benign)

Real upstream `ThreadingHTTPServer` + the real `ShieldProxy` ASGI interface
driven with a real `httpx` upstream connection (no `MockTransport`):

- Before activation: candidate request forwarded (200), upstream counter +1.
- After activation: matching request blocked (403); upstream counter unchanged.
- Benign request forwarded (200).
- Manual expiry and manual removal both stop enforcement (subsequent matching
  requests return 200 and reach upstream).

## Failure injection (test_shield_recovery_failures.py)

| Injection point | API response | Runtime state after |
|-----------------|--------------|---------------------|
| Evidence append raises | 503 | rule PROPOSED (rolled back) |
| Runtime store upsert raises | 503 | rule PROPOSED (rolled back) |

No scenario leaves an ACTIVE runtime rule that the API does not know about.

## Not demonstrated here (honest limitations)

- Docker/PHP lab tests: Docker daemon not running (skipped loudly).
- Browser E2E for the shield screens: Playwright not installed.
- Hosted CI: not run (no push authorized).
- Multi-host deployment: this is loopback-only by design.
