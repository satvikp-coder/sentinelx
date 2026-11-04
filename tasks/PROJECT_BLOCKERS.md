# Current completion status

See [CODEX_COMPLETION_AND_SUBMISSION.md](CODEX_COMPLETION_AND_SUBMISSION.md) for
current fixes, execution evidence and owner-only gates. Earlier entries below
are historical; in particular, Shield no longer universally rejects activation,
and GitHub Actions is configured. Do not describe CI as green without the
actual workflow result for the integrated SHA.

---

# Sentinel X — Project Blockers

**Audit date:** 2026-11-04
**Worker branch:** work/ds
**Worker SHA:** ea875f3

---

## BLOCKERS RESOLVED

| Blocker | Resolution |
|---------|------------|
| SDK rejects localhost URLs with ports | `validateBaseUrl` now parses URL and checks hostname, allowing any port |
| SDK expects `rule_ids` field API omits | Made `rule_ids` optional in `RawSidecarDecision`, defaults to `[]` |
| SDK hardcoded "sdk-default" session ID | Removed; `tool()` requires explicit `sessionId` parameter, throws clear `GuardConfigError` if missing |
| Dashboard SSE returns 401 (no auth) | SSE endpoint accepts token query parameter; dashboard passes it in EventSource URL |
| Dashboard Attack Lab crashes | Creates real session + run via API before making decisions; defensive `ruleIds` access |
| Evidence UI: SSE named events not received | Server no longer sends `event:` lines; all events arrive as `message` events via `onmessage` |
| API targets: URL validation bypassable | Proper `urlparse()` host parsing; rejects `http://localhost:80@example.invalid/`, `file://localhost/etc/passwd` |
| API scans: fabricated COMPLETED state | Initial state is `PENDING`; scan execution runs `run_scan()` in background thread |
| API shield: fabricated ACTIVE state | Fail-closed: `approve_shield_rule` rejects all activations with 400 |
| labctl: socket ownership fails open | `_socket_owner_pid(port, host)` requires TCP socket type and matching host address; fail closed on lookup failure |
| fresh_clone_check: copies .env | `.env` and `.env.local` added to EXCLUDE_NAMES |
| Evidence events: action_id string used as UUID | `uuid4()` used for event `id`; `action_id` kept in payload |
| Scan endpoint: hangs when lab unavailable | Scan creates PENDING record; background execution in daemon thread |
| Socket ownership: accepts UDP/non-LISTEN/different address | Requires SOCK_STREAM + LISTEN state; matches host address; fails closed when ownership unknown |
| CI: ModuleNotFoundError sentinelx_agent_guard | Added `pip install -e sdk/python` to CI workflow |
| Shield: no gated activation | Fail-closed: approve_shield_rule rejects all activations with 400 |
| Scan: no execution pipeline | create_scan runs run_scan() in background daemon thread; state transitions PENDING→RUNNING→COMPLETED/FAILED/CANCELLED |
| Shield list: response 500 after approval | Explicit ShieldRuleResponse serialization |
| Shield list: no pagination | _paginate applied before serialization |
| Dashboard: unprocessed @tailwind directives | Replaced with plain CSS utility classes |
| Scan: findings always empty | Internal findings store scan_id; per-scan filtering works |
| Scan: global findings 500 | Native session IDs mapped to deterministic UUIDv5; explicit FindingResponse serialization |
| Scan: cancellation discards accounting | CANCELLED preserved across worker return/exception; actual work recorded |
| Scan: worker exception overwrites CANCELLED | Terminal state serialized across success/error/cancel paths |
| Scan: concurrency unsafe | threading.Lock for cross-thread scan state |
| Scan: budget mismatch | API reports scanner profile budget (500) |

---

## BLOCKERS REQUIRING HUMAN ACTION

### 1. License choice (owner decision)
**Why:** The repository will be made public for hackathon submission. A license file is required.
**Prerequisites:** Owner selects a license (MIT, Apache-2.0, etc.)
**Expected cost/risk:** Low
**Safe command/procedure:** Add LICENSE file to repository root
**Expected evidence:** LICENSE file present
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

## BLOCKERS REQUIRING FEATURE DEVELOPMENT

### 9. Actual shield activation
**Why:** Shield approval endpoint is fail-closed (rejects all activations with 400). Real activation requires:
- Scoped approval bound to exact rule/session/target
- Latest rejection/revocation enforcement
- Benign-replay gate with representative benign traffic
- Actual proxy/runtime integration (ShieldProxy)
- Durable activation evidence
- Kill switch, TTL, automatic expiry
- Safe rollback/fail-closed behavior
**Prerequisites:** Shield proxy runtime integration, benign-replay gate corpus
**Expected cost/risk:** High (new feature development)
**Safe command/procedure:** Implement activate_shield_rule through RuleLifecycle with actual ShieldProxy
**Expected evidence:** Rule transitions PROPOSED→ACTIVE with real runtime enforcement
**Who must authorize/execute:** Owner

---

## NON-BLOCKERS (documented limitations)

| Item | Status | Why not a blocker |
|------|--------|-------------------|
| SDK runtime E2E vs real backend | Not run | Requires starting API server and running SDK against it; unit tests pass |
| Dashboard browser E2E | Not run | Requires Playwright Chromium; unit tests and typecheck/build pass |
| CRLF git apply on Windows | Documented | Linux CRLF patches apply cleanly; Windows git limitation |
| Tailwind v4 @tailwind not processed | Resolved | Replaced with plain CSS utility classes; dashboard builds cleanly |
| LICENSE not chosen | Documented | Owner decision; doesn't affect code correctness |
| Repo not public | Documented | Owner decision; doesn't affect code correctness |
| No live model runs | Documented | All results are from scripted/planned agents; clearly labeled SIMULATED |

---

## RESOLVED IN THIS SESSION

| Blocker | Resolution |
|---------|------------|
| CI: ModuleNotFoundError sentinelx_agent_guard | Added `pip install -e sdk/python` to CI workflow |
| Shield: unsafe gated activation | Removed unsafe shortcut; restored fail-closed (400 rejection) |
| Scan: no execution pipeline | create_scan runs run_scan() in background daemon thread |
| Scan: invalid TargetAuthorization | Target registration now stores verification_token_hash and verified_at |
| Shield list: response 500 after approval | Explicit ShieldRuleResponse serialization |
| Shield list: no pagination | _paginate applied before serialization |
| Dashboard: unprocessed @tailwind directives | Replaced with plain CSS utility classes |
| Scan: findings always empty | Internal findings store scan_id; per-scan filtering works |
| Scan: global findings 500 | Native session IDs mapped to deterministic UUIDv5; explicit FindingResponse serialization |
| Scan: cancellation discards accounting | CANCELLED preserved across worker return/exception; actual work recorded |
| Scan: worker exception overwrites CANCELLED | Terminal state serialized across success/error/cancel paths |
| Scan: concurrency unsafe | threading.Lock for cross-thread scan state |
| Scan: budget mismatch | API reports scanner profile budget (500) |
