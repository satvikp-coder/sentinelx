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

- Stage F1 (evidence persistence): PENDING
- Stage F2 (redaction): PENDING
- Stage F3 (session/run lifecycle): PENDING
- Stage F4 (approval identity): PENDING
- Stage F5 (test isolation): PENDING
- Stage F6 (concurrency): PENDING
- Stage F7 (scenario snapshots): PENDING
- Stage F8 (SSE reconnect): PENDING
- Stage F9 (branch stabilization): PENDING
- Final gate: PENDING
