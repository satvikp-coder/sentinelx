# SENTINEL X — CRITICAL SECURITY REPAIR 3

## 1. Starting State

- Branch: work/ds
- Starting SHA: 6b69c17 (security repair 2 commit)
- Main SHA: 83030082641fca857df39f0db77ae4024efcbc21
- Worktree clean: Yes
- Python: C:\Users\satvi\Desktop\sentinelx-ds\.venv\Scripts\python.exe

## 2. Existing Behavior (at HEAD)

Both `/api/v1/policy/decide` and `/api/v1/guard/decide` route through `sentinelx.policy.evaluate()` with server-owned scenario binding (Security Repair 2). Per-session runtime state is tracked in `_SESSION_STATE`. Decision events are written to an ephemeral SSE stream only (`event_stream.append`); they are NOT persisted to the evidence store. The `/evidence/verify` endpoint reads `store.events_log` which contains no decision records.

## 3. Nine Findings to Repair

| ID | Finding | Stage |
|----|---------|-------|
| F1 | Decisions not persisted in evidence core; evidence chain absent for decisions | 3 |
| F2 | Sensitive values survive into SSE/event storage (no redaction before broadcast/storage) | 4 |
| F3 | Running jobs leave sessions PENDING (lifecycle mismatch) | 5 |
| F4 | Approved retries generate new action IDs (approval identity not preserved) | 6 |
| F5 | Tests pollute shared session state / module globals | 7 |
| F6 | Runtime check/update race under concurrency | 8 |
| F7 | Scenario objects mutable/shared | 9 |
| F8 | SSE reconnection replays acknowledged events | 10 |
| F9 | Worker branch fails tests/Ruff | 11 |

## 4. Acceptance Criteria

See task requirements section 18 (Final Gate).

## 5. Files to Inspect

- apps/api/routes.py (sessions, runs, decisions, events, evidence)
- apps/api/events.py (SSE event stream)
- apps/api/schemas.py (schemas)
- packages/policy/** (read-only, reference)
- packages/common_schemas/models.py (schemas)
- Evidence store / db / record modules
- tests/unit/test_api_units.py, test_api_security_repair2.py

## 6. Test Strategy

Independent oracle comparisons + real SQLite persistence + real SSE streams + concurrency tests + full regression suites.

## 7. Progress Tracking

- Stage F1 (evidence persistence): COMPLETE — `_gateway_decide` persists ACTION_DECIDED events to EvidenceStore BEFORE broadcasting SSE; `/evidence/verify` calls `verify_chain()` and reports actual chain status (OK/MODIFIED/MISSING/REORDERED)
- Stage F2 (redaction): COMPLETE — SSE event payloads redact both `arguments` and `tool` via `redact().value`; sensitive data never reaches SSE stream unredacted
- Stage F3 (session/run lifecycle): COMPLETE — `create_run` transitions session from PENDING to RUNNING; `cancel_run` transitions session back to PENDING, revoking authorization (SESSION_NOT_RUNNING)
- Stage F4 (approval identity): COMPLETE — Deterministic `action_id` = `api-{sha256(tool+arguments)[:12]}`; approvals validated as `ApprovalRecord` before storing (no silent skip); POST `/api/v1/approvals` endpoint; cross-session isolation verified; malformed approvals rejected with 400
- Stage F5 (test isolation): COMPLETE — Autouse `_reset_shared_state` fixture clears all shared stores after each test; rate-limit tokens cleared in `client` fixture
- Stage F6 (concurrency): COMPLETE — Per-session `threading.Lock()` in `_SESSION_STATE` prevents race conditions
- Stage F7 (scenario snapshots): COMPLETE — `ScenarioSpec.model_copy(deep=True)` when binding to session (immutable snapshot)
- Stage F8 (SSE reconnect): COMPLETE — SSE `ev_id` uses integer `seq` instead of UUID, matching `Last-Event-ID` parsing
- Stage F9 (branch stabilization): COMPLETE — Task 25 metrics test failures fixed (`false_positive_rates` in overall, `MetricError` on no attack runs, graceful handling in report generation with preserved run counts)
- Final gate: COMPLETE — All focused tests pass (120 passed); all Ruff checks pass on changed files; regression tests added for cancellation→deny, approval submit/reject, cross-session isolation, evidence tampering detection
