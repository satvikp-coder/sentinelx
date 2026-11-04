# Shield Recovery — SH-01 through SH-08

**Starting SHA:** 28d98a9eaec59ef94860092e0b7107019fdff3d1
**Final SHA (this work):** see `git log -1` (SH-FIX commits below)
**Main/origin-main:** e035f379b246a0d5dbcb7ae57ffc2ab642718052
**Branch:** work/ds — MERGED: NO, PUSHED: NO

## Commits (focused)

| Commit | Scope |
|--------|-------|
| 591ac8d | SH-FIX-B/C/D/E/F: shield engine, runtime coordination, gate safety, redaction |
| 1260039 | SH-FIX-A/D/E/F: canonical shield approval, scoped activation, expiry, redaction |
| ddb9ccb | SH-FIX-G: real public API + proxy E2E tests and failure-injection regressions |
| b319e0b | SH-FIX-C/H: real subprocess proxy E2E + natural TTL mirroring |
| (docs) | SH-FIX-I: recovery documentation (this file + matrix + E2E) |

## Architecture (after repair)

- **Canonical rule store:** API `store.shield_rules` (API state) + shared
  `ShieldRuntimeStore` (SQLite, `SHIELD_RUNTIME_DB`) that both processes open.
- **Approval binding:** `shield_rule:{rule_id}:{rule_digest}` computed by
  `_shield_rule_digest()` over rule_id/route/intent/mode/action. Stored by the
  public approval endpoint; verified exactly by activation.
- **Proxy control plane:** no network control endpoint. The proxy reads the
  shared SQLite store and re-validates payload hashes; it never enforces a row
  it cannot verify.
- **Cross-process communication:** shared file (SQLite WAL) — one writer (API),
  many readers (proxies). Trust boundary: filesystem access = control plane.
- **Runtime acknowledgment:** activation upserts the ACTIVE row and records the
  revision in the API entry; the proxy only enforces verified ACTIVE rows.
- **Activation transaction:** scope check -> kill switch -> gate -> runtime
  install (`RuleLifecycle.activate_rule`, the only ACTIVE assignment) -> durable
  runtime row -> API state -> evidence. Failure at any persistence step
  deactivates the runtime rule (`deactivate_rule`), restores PROPOSED, returns
  503. No untracked ACTIVE rule can remain.
- **Restart recovery:** after an API restart the runtime store still holds the
  authoritative rows; the proxy keeps enforcing verified ACTIVE rows. After a
  proxy restart it re-reads the same store. TTL expiry is filtered at read time
  and mirrored into the API store on list.

## Defect record

| ID | Root cause | Fix | Verified by |
|----|-----------|-----|-------------|
| SH-01 | Public approval stored `rule_id:digest`; activation searched exact `rule_id` | Canonical subject `shield_rule:{rule_id}:{digest}` used by both endpoints | test_shield_approve_valid_approves_rule; test_sh06_approval_subject_is_canonical |
| SH-02 | API singleton disconnected from standalone proxy | Shared `ShieldRuntimeStore`; proxy enforces verified ACTIVE rows; subprocess E2E | test_e2e02_separate_proxy_process_enforces_api_activation |
| SH-03 | Expire/remove updated only API state | Both endpoints propagate to local lifecycle + runtime store; list mirrors TTL | test_e2e_manual_expiry_and_removal_stop_enforcement |
| SH-04 | Evidence persisted after activation; failure left ACTIVE + 500 | Order + compensation: gateway -> install -> persist; failure deactivates + 503 | test_sh04_evidence_failure_rolls_back_runtime; test_sh04_runtime_store_failure_rolls_back |
| SH-05 | Gate rejection built a ticket with empty evidence ids -> ValidationError -> 500 | Gate records a real rejection event and returns a structured result; proposals carry real evidence | test_sh05_gate_rejection_without_evidence_does_not_crash; test_sh05_api_proposal_has_real_evidence |
| SH-06 | Approval lookup searched all sessions; ignored revocation | `session_id` required; exact-subject lookup in that session; latest record must be approve; 24h max age | test_e2e_cross_session_approval_cannot_activate; test_e2e_revoked_approval_cannot_activate; test_e2e_modified_rule_invalidates_approval |
| SH-07 | Raw paths in proxy logs; unredacted API echoes | Proxy log + recorder redact/template paths; rule echoes and evidence payloads redacted | test_sh07_proxy_request_log_redacts_paths; test_sh07_api_response_redacts_rule_echo; test_e2e_sse_activation_event_is_redacted |
| SH-08 | Tests used direct lifecycle calls; no real upstream/proxy/API chain | Real upstream HTTP server + real proxy ASGI + public API tests; real subprocess E2E | test_shield_e2e_public_api.py (12 tests) |

## Full commands and results

Executed with `C:\Users\satvi\Desktop\sentinelx-ds\.venv\Scripts\python.exe`,
fresh external `--basetemp`, `-p no:cacheprovider`.

| Suite | Result |
|-------|--------|
| Shield units (rules/proxy/modes/model/intent/isolation/evidence/detect/config) | all passed |
| test_shield_activation_integration.py | 6 passed |
| test_shield_e2e_public_api.py | 12 passed (includes subprocess E2E) |
| test_shield_recovery_failures.py | 11 passed |
| test_api_units.py + test_api_security_repair2.py | all passed |
| tests/integration/test_labs.py | 26 passed, 8 docker-skipped |
| tests/integration/test_scanner_against_labs.py | 10 passed, 4 docker-skipped |
| Project Ruff | All checks passed |
| Full fast pytest (`-m "not slow"`) | see `tasks/SHIELD_RECOVERY_TEST_MATRIX.md` / final handoff |

## Lab failure root cause (Part 14)

The earlier full-suite failures were caused by a Node lab process
(`node --no-warnings server.js`, PID 24524) **started by this session earlier**
holding `labs/vibe_notes_node/data/notes.db`. The process was identified by its
command line, stopped (only that PID), and lab suites now pass. Codex tooling
Node processes were left untouched. No data was deleted; no reference lab was
modified; no unrelated process was killed.

## Remaining limitations

- Browser E2E for shield screens: Playwright not installed.
- Docker/PHP lab tests: daemon not running (skipped loudly).
- Hosted CI: not run (no push authorized).
- Multi-host deployment: loopback-only by design; documented trust boundary.
- Recommended-mode enforcement is configuration-level: recommend never blocks;
  enforce + activation blocks. Documented in tests.
